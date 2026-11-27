import type { ProviderId } from "./catalog";
import type { ProviderAdapter } from "./types";
import { virusTotalProvider } from "./virustotal";
import { abuseIpDbProvider } from "./abuseipdb";
import {
  urlhausProvider,
  threatFoxProvider,
  malwareBazaarProvider,
} from "./abusech";
import { otxProvider } from "./otx";
import { shodanProvider } from "./shodan";
import { greyNoiseProvider } from "./greynoise";
import { networkRdapProvider } from "./network_rdap";

export const PROVIDER_ADAPTERS: Record<ProviderId, ProviderAdapter> = {
  virustotal: virusTotalProvider,
  abuseipdb: abuseIpDbProvider,
  urlhaus: urlhausProvider,
  threatfox: threatFoxProvider,
  malwarebazaar: malwareBazaarProvider,
  otx: otxProvider,
  shodan: shodanProvider,
  greynoise: greyNoiseProvider,
  network_rdap: networkRdapProvider,
};
