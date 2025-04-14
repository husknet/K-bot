import axios from 'axios';
import geoip from 'geoip-lite';

const SCRAPER_ISPS = [
  "rgt/smp", "tzulo, inc.", "cyber assets fzco", "falco networks b.v.",
  "pjsc rostelecom", "gtd internet s.a.", "meta networks inc", "private layer inc",
  "bucklog sarl", "fbw reseaux fibres inc.", "openvpn", "huawei cloud hongkong region",
  "excitel broadband pvt ltd", "vpn consumer frankfurt, germany", "m nets sal",
  "hostroyale technologies pvt ltd", "the constant company, llc", "bgm",
  "microcom informatique, inc.", "contabo inc", "telecable residencial",
  "network for tor-exit traffic.", "logicweb inc.", "microsoft corp", "google llc",
  "microsoft corporation", "unknown", "barry hamel equipment ltd",
  "charter communications", "dlf cable network", "packethub s.a.", "datacamp s.r.o.",
  "bharti airtel limited", "clouvider", "facebook", "internet archive",
  "quickpacket, llc", "amazon data services singapore", "pjsc mts sverdlovsk region",
  "home_dsl", "amazon data services nova", "m247 ltd berlin infrastructure",
  "bretagne telecom sasu", "m247 ltd - brazil infrastructure",
  "zap-hosting.com - if you want more power", "zap-hosting gmbh", "artic solutions sarl",
  "ucloud", "cox communications inc.", "onyphe sas",
  "internet utilities europe and asia limited", "kyocera avx components (dresden) gmbh",
  "blix group as", "kaopu cloud hk limited", "total server solutions llc",
  "internet utilities africa (pty) ltd", "atria convergence technologies ltd.,", "linode",
  "bayer ag, germany, leverkusen", "terago networks inc.", "zscaler, inc.",
  "bt global communications india private limited-access", "not surf net", "nothing to hide",
  "total play telecomunicaciones sa de cv", "driftnet ltd", "telstra limited", "ovh us llc",
  "tt dotcom sdn bhd", "ovh (nwk)", "zayo bandwidth", "accenture llp", "kyivstar gsm",
  "cascades", "microsoft limited", "netcraft", "rockion llc",
  "sudhana telecommunications private limited", "compass compression services ltd",
  "digitalocean", "amazon technologies inc.", "datacamp limited", "helsinki, finland",
  "northerntel limited partnership", "china unicom shandong province network",
  "china unicom shanghai city network", "china unicom henan province network",
  "kddi corporation", "reliance jio infocomm limited", "linode, llc", "ovh sas",
  "ovh hosting, inc.", "hetzner online gmbh", "alibaba", "oracle corporation",
  "softlayer technologies", "fastly", "cloudflare", "cloudflare london, llc",
  "akamai technologies", "akamai technologies inc.", "hurricane electric", "hostwinds",
  "choopa", "contabo gmbh", "leaseweb", "censys, inc.", "windscribe",
  "hatching international b.v.", "asm technologies", "leaseweb deutschland gmbh",
  "amazon.com, inc.", "amazon data services ireland limited", "scaleway", "vultr", "ubiquity"
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
  if (!userAgent || !ip) return res.status(400).json({ error: 'Missing user_agent or IP.' });

  try {
    // Step 1: User-Agent bot detection
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) => pattern.test(userAgent.toLowerCase()));

    // Step 2: ISP detection
    let isp = 'unknown';
    let isScraperISP = false;

    try {
      const guideResponse = await axios.get(`https://ip.guide/${ip}`);
      const asnData = guideResponse.data?.autonomous_system;
      if (asnData) {
        isp = (asnData.name || asnData.organization || 'unknown').toLowerCase();
        isScraperISP = SCRAPER_ISPS.some((keyword) => isp.includes(keyword));
      }
    } catch (err) {
      console.error('ip.guide lookup failed:', err.message);
    }

    // Step 3: Traffic frequency detection
    const now = Date.now();
    TRAFFIC_DATA[ip] = (TRAFFIC_DATA[ip] || []).filter(
      (timestamp) => now - timestamp < TRAFFIC_TIMEFRAME
    );
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    // Step 4: GeoIP
    const geoData = geoip.lookup(ip);
    const country = geoData?.country || 'Unknown';

    // Final result
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
    console.error('Bot detection error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}
