import axios from 'axios';
import geoip from 'geoip-lite';

// Scraper ISP keywords (lowercase, partial matches allowed)
const SCRAPER_ISPS = [
  "cloudflare", "amazon", "google", "microsoft", "contabo", "linode", "digitalocean", "ovh",
  "softlayer", "akamai", "fastly", "zscaler", "leaseweb", "choopa", "windscribe", "vultr",
  "cyber", "vpn", "scraper", "crawler", "tor", "ubiquity", "netcraft", "censys", "oracle"
];

// Rate limit settings
const TRAFFIC_THRESHOLD = 10;
const TRAFFIC_TIMEFRAME = 30 * 1000; // 30 seconds
const TRAFFIC_DATA = {}; // In-memory IP request tracker

export default async function handler(req, res) {
  // Allow CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { user_agent: userAgent, ip } = req.body;
  if (!userAgent || !ip) return res.status(400).json({ error: 'Missing user_agent or IP.' });

  try {
    // Step 1: Detect bots via User-Agent
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) =>
      pattern.test(userAgent.toLowerCase())
    );

    // Step 2: Detect bots via ISP (from ip.guide)
    let isp = 'unknown';
    let isScraperISP = false;

    try {
      const guideResponse = await axios.get(`https://ip.guide/${ip}`);
      const asnData = guideResponse.data?.autonomous_system;
      if (asnData) {
        isp = asnData.name || asnData.organization || 'unknown';

        // Normalize for fuzzy matching
        const cleanISP = isp.toLowerCase().replace(/[.,\s-]/g, '');
        isScraperISP = SCRAPER_ISPS.some((keyword) => {
          const normalizedKeyword = keyword.toLowerCase().replace(/[.,\s-]/g, '');
          return cleanISP.includes(normalizedKeyword);
        });
      }
    } catch (err) {
      console.error('❌ ISP lookup failed from ip.guide:', err.message);
    }

    // Step 3: Detect suspicious traffic
    const now = Date.now();
    TRAFFIC_DATA[ip] = (TRAFFIC_DATA[ip] || []).filter(
      (timestamp) => now - timestamp < TRAFFIC_TIMEFRAME
    );
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    // Step 4: GeoIP backup
    const geoData = geoip.lookup(ip);
    const country = geoData?.country || 'Unknown';

    // Logging for debugging
    console.log(`[Bot Detection] IP: ${ip}, ISP: ${isp}, Country: ${country}, UA: ${userAgent}`);
    console.log(`[Match Flags] Bot UA: ${isBotUserAgent}, Scraper ISP: ${isScraperISP}, Suspicious Traffic: ${isSuspiciousTraffic}`);

    // Final decision
    const isBot = isBotUserAgent || isScraperISP || isSuspiciousTraffic;

    return res.status(200).json({
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
    console.error('❌ Bot detection API error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
