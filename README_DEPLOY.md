# Malabar Sentinel — Deployment Notes

## Railway Environment Variables (set in Railway dashboard)
| Variable | Value | Notes |
|---|---|---|
| SOC_MASTER_KEY | your-secret-key | Dashboard + API authentication |
| AGENT_KEY | your-agent-key | Agent authentication |
| PORT | (auto-set by Railway) | Do not set manually |

## After Deploy
1. Copy your Railway URL (e.g. https://malabar-sentinel.up.railway.app)
2. Set that as `server_url` in the agent GUI or `config/agent.json`
3. Update the dashboard Settings → Server URL to the Railway URL
4. Change API keys from defaults before going live
