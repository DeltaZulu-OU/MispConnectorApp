/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace MispConnector
{
    public sealed class App : IDnsApplication, IDnsRequestBlockingHandler
    {
        #region variables

        string _domainCacheFilePath;
        Config _config;
        IDnsServer _dnsServer;
        IocSnapshot _iocSnapshot = IocSnapshot.Empty;
        HttpClient _httpClient;

        Uri _mispApiUrl;
        Uri _mispServerUrl;

        DnsSOARecordData _soaRecord;
        TimeSpan _updateInterval;
        Task _updateLoopTask;

        CancellationTokenSource _appShutdownCts;
        #endregion variables

        #region IDisposable

        public void Dispose()
        {
            _appShutdownCts?.Cancel();
            try
            {
                if (_updateLoopTask != null)
                {
                    try
                    {
                        _updateLoopTask?.WaitAsync(TimeSpan.FromSeconds(2))
                                       .GetAwaiter()
                                       .GetResult();
                    }
                    catch { }
                }
            }
            catch
            {
            }
            finally
            {
                _appShutdownCts?.Dispose();
                _httpClient?.Dispose();
            }
        }

        #endregion IDisposable

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            try
            {
                JsonSerializerOptions options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                Config newConfig = JsonSerializer.Deserialize<Config>(config, options);

                Validator.ValidateObject(newConfig, new ValidationContext(newConfig), validateAllProperties: true);

                string configDir = _dnsServer.ApplicationFolder;
                Directory.CreateDirectory(configDir);
                string domainCacheFilePath = Path.Combine(configDir, "misp_domain_cache.txt");

                TimeSpan updateInterval = ParseUpdateInterval(newConfig.UpdateInterval);

                string mispServerUrl = newConfig.MispServerUrl.EndsWith("/", StringComparison.Ordinal)
                    ? newConfig.MispServerUrl
                    : newConfig.MispServerUrl + "/";
                Uri newMispServerUrl = new Uri(mispServerUrl);
                Uri newMispApiUrl = new Uri(newMispServerUrl, "attributes/restSearch");

                if (_appShutdownCts != null)
                {
                    _appShutdownCts.Cancel();
                    if (_updateLoopTask != null)
                    {
                        try
                        {
                            await _updateLoopTask.WaitAsync(TimeSpan.FromSeconds(2));
                        }
                        catch
                        {
                        }
                    }

                    _appShutdownCts.Dispose();
                    _appShutdownCts = null;
                    _updateLoopTask = null;
                }

                _httpClient?.Dispose();

                _config = newConfig;
                _domainCacheFilePath = domainCacheFilePath;
                _updateInterval = updateInterval;
                _mispServerUrl = newMispServerUrl;
                _mispApiUrl = newMispApiUrl;
                _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, 60);
                _httpClient = CreateHttpClient(_mispServerUrl, _config.DisableTlsValidation);

                await LoadBlocklistFromCacheAsync();
                _appShutdownCts = new CancellationTokenSource();

                // We do not await this, as it's designed to run for the lifetime of the app.
                _updateLoopTask = StartUpdateLoopAsync(_appShutdownCts.Token);
                Task _ = _updateLoopTask.ContinueWith(t =>
                {
                    if (t.IsFaulted)
                    {
                        _dnsServer.WriteLog($"FATAL: Update loop terminated unexpectedly: {t.Exception?.GetBaseException().Message}");
                        _dnsServer.WriteLog(t.Exception);
                    }
                }, TaskContinuationOptions.OnlyOnFaulted);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"FATAL: MISP Connector failed to initialize. Check configuration. Error: {ex.Message}");
                _dnsServer.WriteLog(ex);
            }
        }

        // No allowlist override in this app.
        // ProcessRequestAsync handles blocking.
        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            return Task.FromResult(false);
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (_config?.EnableBlocking != true)
            {
                return Task.FromResult<DnsDatagram>(null);
            }

            DnsQuestionRecord question = request.Question[0];
            IocSnapshot snapshot = _iocSnapshot;
            if (!IsDomainBlocked(snapshot, question.Name, out string blockedDomain, out uint eventId))
            {
                return Task.FromResult<DnsDatagram>(null);
            }

            bool fullContext = string.Equals(_config.ReportContext, "full", StringComparison.Ordinal);
            string eventContext = null;
            if (fullContext && eventId != 0)
                snapshot.EventContexts.TryGetValue(eventId, out eventContext);

            uint reportedEventId = string.Equals(_config.ReportContext, "none", StringComparison.Ordinal) ? 0 : eventId;

            // Keep EDE text short to avoid inflating UDP responses. The DNS question already carries the blocked domain.
            EDnsOption[] options = null;
            if (_config.AddExtendedDnsError && request.EDNS is not null)
            {
                string edeReport = TruncateUtf8(BuildBlockingReport(null, reportedEventId, eventContext), 128);
                options = new EDnsOption[] { new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, edeReport)) };
            }

            DnsResourceRecord[] answer = null;
            DnsResourceRecord[] authority = null;
            bool authoritative = false;
            DnsResponseCode rCode;
            if (_config.AllowTxtBlockingReport && question.Type == DnsResourceRecordType.TXT)
            {
                string txtReport = TruncateUtf8(BuildBlockingReport(blockedDomain, reportedEventId, eventContext), 512);
                answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _config.BlockingAnswerTtl, new DnsTXTRecordData(txtReport)) };
                rCode = DnsResponseCode.NoError;
            }
            else
            {
                authority = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.SOA, question.Class, _config.BlockingAnswerTtl, _soaRecord) };
                rCode = DnsResponseCode.NxDomain;
                authoritative = true;
            }

            return BlockResponse(request: request, options: options, authority: authority, answer: answer, authoritativeAnswer: authoritative, rCode: rCode);
        }

        private Task<DnsDatagram> BlockResponse(DnsDatagram request, EDnsOption[] options, DnsResourceRecord[] authority, DnsResourceRecord[] answer, bool authoritativeAnswer, DnsResponseCode rCode)
        {
            return Task.FromResult(new DnsDatagram(
                            ID: request.Identifier,
                            isResponse: true,
                            OPCODE: DnsOpcode.StandardQuery,
                            authoritativeAnswer: authoritativeAnswer,
                            truncation: false,
                            recursionDesired: request.RecursionDesired,
                            recursionAvailable: true,
                            authenticData: false,
                            checkingDisabled: false,
                            RCODE: rCode,
                            question: request.Question,
                            answer: answer,
                            authority: authority,
                            additional: null,
                            udpPayloadSize: request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize,
                            ednsFlags: EDnsHeaderFlags.None,
                            options: options
                        ));
        }

        #endregion public

        #region private

        private async Task StartUpdateLoopAsync(CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(Random.Shared.Next(5, 30)), cancellationToken);
            using (PeriodicTimer timer = new PeriodicTimer(_updateInterval))
            {
                while (true)
                {
                    try
                    {
                        await UpdateIocsAsync(cancellationToken);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        _dnsServer.WriteLog("Update loop is shutting down gracefully.");
                        break;
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog($"FATAL: The MispConnector update task failed unexpectedly. Error: {ex.Message}");
                        _dnsServer.WriteLog(ex);
                    }

                    if (!await timer.WaitForNextTickAsync(cancellationToken))
                        break;
                }
            }
        }

        private static TimeSpan ParseUpdateInterval(string interval)
        {
            if (string.IsNullOrWhiteSpace(interval) || interval.Length < 2)
            {
                throw new FormatException("Update interval is not in a valid format (e.g., '60m', '2h', '7d').");
            }

            string unit = interval.Substring(interval.Length - 1).ToLowerInvariant();
            string valueString = interval.Substring(0, interval.Length - 1);

            if (!int.TryParse(valueString, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) || value <= 0)
            {
                throw new FormatException($"Invalid numeric value '{valueString}' in update interval.");
            }

            switch (unit)
            {
                case "m":
                    return TimeSpan.FromMinutes(value);

                case "h":
                    return TimeSpan.FromHours(value);

                case "d":
                    return TimeSpan.FromDays(value);

                default:
                    throw new FormatException($"Invalid unit '{unit}' in update interval. Allowed units are 'm', 'h', 'd'.");
            }
        }

        private async Task<bool> CheckTcpPortAsync(Uri serverUri, CancellationToken cancellationToken)
        {
            string host = serverUri.DnsSafeHost;
            int port = serverUri.Port;
            TimeSpan timeout = TimeSpan.FromSeconds(5);

            _dnsServer.WriteLog($"Performing pre-flight TCP check for {host}:{port} with a {timeout.TotalSeconds}-second timeout...");

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(timeout);

                using var client = new TcpClient();
                await client.ConnectAsync(host, port, cts.Token);

                _dnsServer.WriteLog($"Pre-flight TCP check successful for {host}:{port}.");
                return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                _dnsServer.WriteLog($"ERROR: Pre-flight TCP check failed: Connection to {host}:{port} timed out after {timeout.TotalSeconds} seconds. Check firewall rules or network route.");
                return false;
            }
            catch (SocketException ex)
            {
                _dnsServer.WriteLog($"ERROR: Pre-flight TCP check failed: A network error occurred for {host}:{port}. Error: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"ERROR: An unexpected error occurred during the pre-flight TCP check for {host}:{port}. Error: {ex.Message}");
                return false;
            }
        }

        private HttpClient CreateHttpClient(Uri serverUrl, bool disableTlsValidation)
        {
            HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            handler.Proxy = _dnsServer.Proxy;
            handler.NetworkType = _dnsServer.IPv6Mode == IPv6Mode.Preferred ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
            handler.DnsClient = _dnsServer;

            if (disableTlsValidation)
            {
                handler.InnerHandler.SslOptions.RemoteCertificateValidationCallback = delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
                {
                    return true;
                };

                _dnsServer.WriteLog($"WARNING: TLS certificate validation is DISABLED for MISP server: {serverUrl}");
            }

            return new HttpClient(handler);
        }

        private async Task<IocSnapshot> FetchIocFromMispAsync(CancellationToken cancellationToken)
        {
            int page = 1;
            int limit = _config.PaginationLimit;
            bool fullContext = string.Equals(_config.ReportContext, "full", StringComparison.Ordinal);
            IocSnapshot current = _iocSnapshot;
            int initialDomainCapacity = current.Domains.Count > 0 ? current.Domains.Count : limit;
            Dictionary<string, uint> iocs = new Dictionary<string, uint>(initialDomainCapacity, StringComparer.OrdinalIgnoreCase);
            Dictionary<uint, string> eventContexts = new Dictionary<uint, string>(current.EventContexts.Count);

            _dnsServer.WriteLog($"Starting paginated fetch from MISP API with a page size of {limit}...");
            const int maxRetries = 3;

            while (true)
            {
                int attempt = 0;
                MispResponse mispResponse = null;

                while (attempt < maxRetries)
                {
                    attempt++;
                    try
                    {
                        MispRequestBody requestBody = new MispRequestBody
                        {
                            ReturnFormat = "json",
                            Type = "domain",
                            To_ids = true,
                            Deleted = false,
                            Published = true,
                            Last = _config.MaxIocAge,
                            IncludeContext = fullContext,
                            Limit = limit,
                            Page = page
                        };
                        StringContent requestContent = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

                        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, _mispApiUrl) { Content = requestContent };
                        request.Headers.Add("Authorization", _config.MispApiKey);
                        request.Headers.Add("Accept", "application/json");

                        using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken);

                        if (!response.IsSuccessStatusCode)
                        {
                            string errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
                            throw new HttpRequestException($"MISP API returned a non-success status code: {(int)response.StatusCode}. Body: {errorBody}", null, response.StatusCode);
                        }

                        await using (Stream responseStream = await response.Content.ReadAsStreamAsync(cancellationToken))
                            mispResponse = await JsonSerializer.DeserializeAsync<MispResponse>(responseStream, cancellationToken: cancellationToken);

                        break;
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (HttpRequestException ex)
                    {
                        if (!await HandleRetry(ex, page, maxRetries, attempt, cancellationToken))
                            throw;
                    }
                    catch (SocketException ex)
                    {
                        if (!await HandleRetry(ex, page, maxRetries, attempt, cancellationToken))
                            throw;
                    }
                }

                List<MispAttribute> attributes = (mispResponse?.Response?.Attribute) ??
                    throw new InvalidDataException("Invalid or unexpected MISP response schema.");

                if (attributes.Count == 0)
                    break;

                foreach (MispAttribute attribute in attributes)
                {
                    string ioc = attribute.Value?.Trim();
                    if (string.IsNullOrEmpty(ioc) || !DnsClient.IsDomainNameValid(ioc))
                        continue;

                    uint eventId = ParseEventId(attribute.Event?.Id ?? attribute.EventId);

                    if (fullContext && eventId != 0 && !eventContexts.ContainsKey(eventId))
                    {
                        string context = BuildEventContext(attribute.Event);
                        if (!string.IsNullOrEmpty(context))
                            eventContexts.Add(eventId, context);
                    }

                    if (iocs.TryGetValue(ioc, out uint existingEventId))
                    {
                        if (eventId == 0 || (existingEventId != 0 && existingEventId <= eventId))
                            continue;

                        iocs[ioc] = eventId;
                    }
                    else
                    {
                        iocs.Add(ioc, eventId);
                    }
                }

                page++;
            }

            iocs.TrimExcess();
            eventContexts.TrimExcess();
            _dnsServer.WriteLog($"Finished paginated fetch. Retained {iocs.Count} unique domain IOCs and {eventContexts.Count} event context records.");
            return new IocSnapshot(iocs, eventContexts);
        }

        private async Task<bool> HandleRetry(
            Exception ex,
            int page,
            int maxRetries,
            int attempt,
            CancellationToken cancellationToken)
        {
            _dnsServer.WriteLog(
                $"WARNING: A transient network error occurred on page {page}, " +
                $"attempt {attempt}/{maxRetries}. Error: {ex.Message}");

            if (attempt < maxRetries)
            {
                TimeSpan delay =
                    TimeSpan.FromSeconds(Math.Pow(2, attempt)) +
                    TimeSpan.FromMilliseconds(Random.Shared.Next(0, 1000));

                _dnsServer.WriteLog(
                    $"Waiting for {delay.TotalSeconds:F1} seconds before retrying...");

                await Task.Delay(delay, cancellationToken);
                return true;
            }

            _dnsServer.WriteLog(
                $"ERROR: Failed to fetch page {page} after {maxRetries} attempts.");

            return false;
        }

        private static bool IsDomainBlocked(IocSnapshot snapshot, string domain, out string foundDomain, out uint eventId)
        {
            Dictionary<string, uint>.AlternateLookup<ReadOnlySpan<char>> lookup =
                snapshot.Domains.GetAlternateLookup<ReadOnlySpan<char>>();

            ReadOnlySpan<char> currentSpan = domain.AsSpan();

            while (true)
            {
                if (lookup.TryGetValue(currentSpan, out foundDomain, out eventId))
                    return true;

                int dotIndex = currentSpan.IndexOf('.');
                if (dotIndex < 0)
                    break;

                currentSpan = currentSpan.Slice(dotIndex + 1);
            }

            foundDomain = null;
            eventId = 0;
            return false;
        }

        private static string BuildBlockingReport(string domain, uint eventId, string eventContext)
        {
            StringBuilder report = new StringBuilder(256);
            report.Append("source=misp");

            if (eventId != 0)
            {
                report.Append(";event=");
                report.Append(eventId.ToString(CultureInfo.InvariantCulture));
            }

            if (!string.IsNullOrEmpty(domain))
            {
                report.Append(";domain=");
                report.Append(domain);
            }

            if (!string.IsNullOrEmpty(eventContext))
                report.Append(eventContext);

            return report.ToString();
        }

        private static string BuildEventContext(MispEvent mispEvent)
        {
            if (mispEvent is null ||
                !string.Equals(mispEvent.Distribution, "3", StringComparison.Ordinal) ||
                HasRestrictedTlp(mispEvent.Tags))
                return null;

            StringBuilder context = new StringBuilder(192);
            AppendReportField(context, "org", NormalizeReportValue(mispEvent.Orgc?.Name, 80));
            AppendReportField(context, "threat", GetThreatLevelName(mispEvent.ThreatLevelId));
            AppendReportField(context, "info", NormalizeReportValue(mispEvent.Info, 120));
            AppendReportField(context, "tags", BuildEventTags(mispEvent.Tags));
            return context.Length == 0 ? null : context.ToString();
        }

        private static bool HasRestrictedTlp(List<MispTag> tags)
        {
            if (tags is null)
                return false;

            foreach (MispTag tag in tags)
            {
                string name = tag?.Name?.Trim();
                if (string.IsNullOrEmpty(name) || !name.StartsWith("tlp:", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!name.Equals("tlp:clear", StringComparison.OrdinalIgnoreCase) &&
                    !name.Equals("tlp:white", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static void AppendReportField(StringBuilder report, string name, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return;

            report.Append(';');
            report.Append(name);
            report.Append('=');
            report.Append(value);
        }

        private static string NormalizeReportValue(string value, int maxBytes)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            string trimmed = value.Trim();
            StringBuilder cleaned = new StringBuilder(trimmed.Length);
            foreach (char c in trimmed)
            {
                if (c == ';')
                    cleaned.Append(',');
                else if (c == '=')
                    cleaned.Append(':');
                else if (char.IsControl(c))
                    cleaned.Append(' ');
                else
                    cleaned.Append(c);
            }

            return TruncateUtf8(cleaned.ToString(), maxBytes);
        }

        private static string BuildEventTags(List<MispTag> tags)
        {
            if (tags is null || tags.Count == 0)
                return null;

            const int maxTagBytes = 160;
            int usedBytes = 0;
            StringBuilder result = new StringBuilder(96);
            foreach (MispTag tag in tags)
            {
                string name = NormalizeReportValue(tag?.Name, 64);
                if (string.IsNullOrEmpty(name))
                    continue;

                int nameBytes = Encoding.UTF8.GetByteCount(name);
                int separatorBytes = result.Length > 0 ? 1 : 0;
                if (usedBytes + separatorBytes + nameBytes > maxTagBytes)
                    break;

                if (separatorBytes != 0)
                    result.Append(',');

                result.Append(name);
                usedBytes += separatorBytes + nameBytes;
            }

            return result.Length == 0 ? null : result.ToString();
        }

        private static string TruncateUtf8(string value, int maxBytes)
        {
            if (string.IsNullOrEmpty(value) || Encoding.UTF8.GetByteCount(value) <= maxBytes)
                return value;

            const string ellipsis = "...";
            int availableBytes = maxBytes - ellipsis.Length;
            Span<byte> buffer = stackalloc byte[availableBytes];
            Encoding.UTF8.GetEncoder().Convert(value.AsSpan(), buffer, true, out int charsUsed, out _, out _);
            return value.Substring(0, charsUsed) + ellipsis;
        }

        private static uint ParseEventId(string eventId)
        {
            return uint.TryParse(eventId, NumberStyles.None, CultureInfo.InvariantCulture, out uint value) ? value : 0;
        }

        private static string GetThreatLevelName(string threatLevelId)
        {
            return threatLevelId switch
            {
                "1" => "high",
                "2" => "medium",
                "3" => "low",
                "4" => "undefined",
                _ => null
            };
        }

        private async Task LoadBlocklistFromCacheAsync()
        {
            if (!File.Exists(_domainCacheFilePath))
                return;

            try
            {
                Dictionary<string, uint> domains = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);

                await foreach (string line in File.ReadLinesAsync(_domainCacheFilePath))
                {
                    string domain = line.Trim();
                    if (domain.Length > 0 && DnsClient.IsDomainNameValid(domain))
                        domains[domain] = 0;
                }

                domains.TrimExcess();
                Interlocked.Exchange(ref _iocSnapshot, new IocSnapshot(domains, new Dictionary<uint, string>()));
                _dnsServer.WriteLog($"MISP Connector: Loaded {domains.Count} domains from cache.");
            }
            catch (IOException ex)
            {
                _dnsServer.WriteLog($"ERROR: Failed to read cache file '{_domainCacheFilePath}'. Error: {ex.Message}");
            }
        }

        private async Task UpdateIocsAsync(CancellationToken cancellationToken)
        {
            if (!await CheckTcpPortAsync(_mispServerUrl, cancellationToken))
                return;

            _dnsServer.WriteLog("MISP Connector: Starting IOC update...");

            IocSnapshot candidate = await FetchIocFromMispAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            if (IocDataEquals(_iocSnapshot, candidate))
            {
                _dnsServer.WriteLog("MISP data has not changed. No update to current blocklist or cache is necessary.");
                return;
            }

            await WriteIocsToCacheAsync(candidate.Domains.Keys, cancellationToken);
            Interlocked.Exchange(ref _iocSnapshot, candidate);
            _dnsServer.WriteLog($"MISP Connector: Successfully updated blocklist with {candidate.Domains.Count} domains from {candidate.EventContexts.Count} MISP event context records.");
        }

        private static bool IocDataEquals(IocSnapshot current, IocSnapshot candidate)
        {
            if (current.Domains.Count != candidate.Domains.Count || current.EventContexts.Count != candidate.EventContexts.Count)
                return false;

            foreach (KeyValuePair<string, uint> item in candidate.Domains)
            {
                if (!current.Domains.TryGetValue(item.Key, out uint existing) || existing != item.Value)
                    return false;
            }

            foreach (KeyValuePair<uint, string> item in candidate.EventContexts)
            {
                if (!current.EventContexts.TryGetValue(item.Key, out string existing) || !string.Equals(existing, item.Value, StringComparison.Ordinal))
                    return false;
            }

            return true;
        }

        private async Task WriteIocsToCacheAsync(IEnumerable<string> iocs, CancellationToken cancellationToken)
        {
            string tempPath = _domainCacheFilePath + ".tmp";
            await File.WriteAllLinesAsync(tempPath, iocs, cancellationToken);
            File.Move(tempPath, _domainCacheFilePath, true);
        }

        #endregion private

        #region properties

        public string Description
        {
            get
            {
                return "A focused connector that imports domain IOCs from a MISP server to block malicious domains using direct REST API calls.";
            }
        }

        #endregion properties

        private class Config
        {
            [JsonPropertyName("addExtendedDnsError")]
            public bool AddExtendedDnsError { get; set; } = true;

            [JsonPropertyName("allowTxtBlockingReport")]
            public bool AllowTxtBlockingReport { get; set; } = true;

            [JsonPropertyName("disableTlsValidation")]
            public bool DisableTlsValidation { get; set; } = false;

            [JsonPropertyName("enableBlocking")]
            public bool EnableBlocking { get; set; } = true;

            [JsonPropertyName("maxIocAge")]
            [Required(ErrorMessage = "maxIocAge is a required configuration property.")]
            [RegularExpression(@"^\d+[mhd]$", ErrorMessage = "Invalid interval format. Use a number followed by 'm', 'h', or 'd' (e.g., '90m', '2h', '7d').", MatchTimeoutInMilliseconds = 3000)]
            public string MaxIocAge { get; set; }

            [JsonPropertyName("blockingAnswerTtl")]
            [Range(30, 86400, ErrorMessage = "blockingAnswerTtl must be between 30 and 86400 seconds.")]
            public uint BlockingAnswerTtl { get; set; } = 30;

            [JsonPropertyName("mispApiKey")]
            [Required(ErrorMessage = "mispApiKey is a required configuration property.")]
            [MinLength(1, ErrorMessage = "mispApiKey cannot be empty.")]
            public string MispApiKey { get; set; }

            [JsonPropertyName("mispServerUrl")]
            [Required(ErrorMessage = "mispServerUrl is a required configuration property.")]
            [Url(ErrorMessage = "mispServerUrl must be a valid URL.")]
            public string MispServerUrl { get; set; }

            [JsonPropertyName("paginationLimit")]
            [Range(1, 10000, ErrorMessage = "paginationLimit must be between 1 and 10000.")]
            public int PaginationLimit { get; set; } = 1000;

            [JsonPropertyName("reportContext")]
            [Required(ErrorMessage = "reportContext is a required configuration property.")]
            [RegularExpression(@"^(none|event-id|full)$", ErrorMessage = "reportContext must be 'none', 'event-id', or 'full'.", MatchTimeoutInMilliseconds = 3000)]
            public string ReportContext { get; set; } = "event-id";

            [JsonPropertyName("updateInterval")]
            [Required(ErrorMessage = "updateInterval is a required configuration property.")]
            [RegularExpression(@"^\d+[mhd]$", ErrorMessage = "Invalid interval format. Use a number followed by 'm', 'h', or 'd' (e.g., '90m', '2h', '7d').", MatchTimeoutInMilliseconds = 3000)]
            public string UpdateInterval { get; set; }
        }

        private sealed class IocSnapshot
        {
            public static readonly IocSnapshot Empty = new IocSnapshot(
                new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase),
                new Dictionary<uint, string>());

            public IocSnapshot(Dictionary<string, uint> domains, Dictionary<uint, string> eventContexts)
            {
                Domains = domains;
                EventContexts = eventContexts;
            }

            public Dictionary<string, uint> Domains { get; }
            public Dictionary<uint, string> EventContexts { get; }
        }

        private class MispAttribute
        {
            [JsonPropertyName("value")]
            public string Value { get; set; }

            [JsonPropertyName("event_id")]
            public string EventId { get; set; }

            [JsonPropertyName("Event")]
            public MispEvent Event { get; set; }
        }

        private class MispEvent
        {
            [JsonPropertyName("id")]
            public string Id { get; set; }

            [JsonPropertyName("info")]
            public string Info { get; set; }

            [JsonPropertyName("threat_level_id")]
            public string ThreatLevelId { get; set; }

            [JsonPropertyName("distribution")]
            public string Distribution { get; set; }

            [JsonPropertyName("Orgc")]
            public MispOrganisation Orgc { get; set; }

            [JsonPropertyName("Tag")]
            public List<MispTag> Tags { get; set; }
        }

        private class MispOrganisation
        {
            [JsonPropertyName("name")]
            public string Name { get; set; }
        }

        private class MispTag
        {
            [JsonPropertyName("name")]
            public string Name { get; set; }
        }

        private class MispRequestBody
        {
            [JsonPropertyName("returnFormat")]
            public string ReturnFormat { get; set; }

            [JsonPropertyName("deleted")]
            public bool Deleted { get; set; }

            [JsonPropertyName("published")]
            public bool Published { get; set; }

            [JsonPropertyName("last")]
            public string Last { get; set; }

            [JsonPropertyName("includeContext")]
            public bool IncludeContext { get; set; }

            [JsonPropertyName("limit")]
            public int Limit { get; set; }

            [JsonPropertyName("page")]
            public int Page { get; set; }

            [JsonPropertyName("to_ids")]
            public bool To_ids { get; set; }

            [JsonPropertyName("type")]
            public string Type { get; set; }
        }

        private class MispResponse
        {
            [JsonPropertyName("response")]
            public MispResponseData Response { get; set; }
        }

        private class MispResponseData
        {
            [JsonPropertyName("Attribute")]
            public List<MispAttribute> Attribute { get; set; }
        }
    }
}