import axios from 'axios';
import geoip from 'geoip-lite';

const SCRAPER_ISPS = [
  "cogent communications, inc.",
  "worldstream bv",
  "amazon.com",
  "global secure layer",
  "rgt/smp",
  "tzulo inc",
  "cyber assets fzco",
  "falco networks b.v.",
  "pjsc rostelecom",
  "gtd internet s.a.",
  "meta networks inc",
  "private layer inc",
  "bucklog sarl",
  "fbw reseaux fibres inc",
  "openvpn",
  "huawei cloud hongkong region",
  "excitel broadband pvt ltd",
  "vpn consumer frankfurt germany",
  "m nets sal",
  "hostroyale technologies pvt ltd",
  "the constant company llc",
  "bgm",
  "microcom informatique inc",
  "contabo inc",
  "telecable residencial",
  "network for tor-exit traffic",
  "logicweb inc",
  "microsoft corp",
  "microsoft corporation",
  "microsoft limited",
  "microsoft",
  "google llc",
  "unknown",
  "barry hamel equipment ltd",
  "charter communications",
  "dlf cable network",
  "packethub s.a.",
  "datacamp s.r.o.",
  "bharti airtel limited",
  "clouvider",
  "facebook",
  "internet archive",
  "quickpacket llc",
  "amazon data services singapore",
  "pjsc mts sverdlovsk region",
  "home_dsl",
  "amazon data services nova",
  "m247 ltd berlin infrastructure",
  "bretagne telecom sasu",
  "m247 ltd - brazil infrastructure",
  "zap-hosting.com - if you want more power",
  "zap-hosting gmbh",
  "artic solutions sarl",
  "ucloud",
  "cox communications inc",
  "onyphe sas",
  "internet utilities europe and asia limited",
  "kyocera avx components (dresden) gmbh",
  "blix group as",
  "kaopu cloud hk limited",
  "total server solutions llc",
  "internet utilities africa (pty) ltd",
  "atria convergence technologies ltd",
  "linode",
  "linode llc",
  "bayer ag germany leverkusen",
  "terago networks inc",
  "zscaler inc",
  "bt global communications india private limited-access",
  "not surf net",
  "nothing to hide",
  "total play telecomunicaciones sa de cv",
  "driftnet ltd",
  "telstra limited",
  "ovh us llc",
  "tt dotcom sdn bhd",
  "ovh (nwk)",
  "ovh sas",
  "ovh hosting inc",
  "zayo bandwidth",
  "accenture llp",
  "kyivstar gsm",
  "cascades",
  "netcraft",
  "rockion llc",
  "sudhana telecommunications private limited",
  "compass compression services ltd",
  "digitalocean",
  "amazon technologies inc",
  "datacamp limited",
  "helsinki finland",
  "northerntel limited partnership",
  "china unicom shandong province network",
  "china unicom shanghai city network",
  "china unicom henan province network",
  "kddi corporation",
  "reliance jio infocomm limited",
  "hetzner online gmbh",
  "alibaba",
  "oracle corporation",
  "softlayer technologies",
  "fastly",
  "cloudflare",
  "cloudflare london llc",
  "akamai technologies",
  "akamai technologies inc",
  "hurricane electric",
  "hostwinds",
  "choopa",
  "contabo gmbh",
  "leaseweb",
  "leaseweb deutschland gmbh",
  "censys inc",
  "windscribe",
  "hatching international b.v.",
  "asm technologies",
  "amazon.com inc",
  "amazon data services ireland limited",
  "scaleway",
  "vultr",
  "ubiquity"
];

const TRAFFIC_THRESHOLD = 10;
const TRAFFIC_TIMEFRAME = 30 * 1000;
const TRAFFIC_DATA = {};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { user_agent: userAgent, ip } = req.body;

  if (!userAgent || !ip) {
    return res.status(400).json({ error: 'Invalid request: Missing user_agent or IP.' });
  }

  try {
    // Step 1: Bot detection via User-Agent patterns
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) =>
      pattern.test(userAgent.toLowerCase())
    );

    // Step 2: IPify lookup
    const IPIFY_API_KEY = 'at_6Bx93cOoKa1tdYTTbcyDY1hVGNfmT'; // Replace with your real key
    let isp = 'Unknown';
    let country = 'Unknown';
    let isScraperISP = false;

    try {
      const response = await axios.get('https://geo.ipify.org/api/v2/country', {
        params: {
          apiKey: IPIFY_API_KEY,
          ipAddress: ip,
        },
      });

      const data = response.data;
      isp = data.isp || 'Unknown';
      country = data.location?.country || 'Unknown';

      // Normalized matching
      isScraperISP = SCRAPER_ISPS.some((knownISP) =>
        isp.toLowerCase().includes(knownISP)
      );
    } catch (err) {
      console.error('IPify lookup failed:', err.message);
    }

    // Step 3: Traffic abuse logic
    const now = Date.now();
    if (!TRAFFIC_DATA[ip]) TRAFFIC_DATA[ip] = [];
    TRAFFIC_DATA[ip] = TRAFFIC_DATA[ip].filter((ts) => now - ts < TRAFFIC_TIMEFRAME);
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    // Step 4: Backup geo
    const geoData = geoip.lookup(ip);
    if (!country || country === 'Unknown') {
      country = geoData?.country || 'Unknown';
    }

    console.log(`Detection Details for IP: ${ip}`);
    console.log(`ISP: ${isp}`);
    console.log(`User-Agent: ${userAgent}`);
    console.log(`Country: ${country}`);
    console.log(`Is Bot (User-Agent): ${isBotUserAgent}`);
    console.log(`Is Scraper ISP: ${isScraperISP}`);
    console.log(`Is Suspicious Traffic: ${isSuspiciousTraffic}`);

    const isBot = isBotUserAgent || isScraperISP || isSuspiciousTraffic;

    res.status(200).json({
      is_bot: isBot,
      country,
      details: {
        isp,
        bot_user_agent: isBotUserAgent,
        scraper_isp: isScraperISP,
        suspicious_traffic: isSuspiciousTraffic,
      },
    });
  } catch (error) {
    console.error('Error processing bot detection:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}
