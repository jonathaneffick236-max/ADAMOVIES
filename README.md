# ADAMOVIES Backend

## Render
Build: `npm install`
Start: `npm start`

Required environment variables: `DATABASE_URL`, `JWT_SECRET`, `TMDB_API_KEY`, `MUX_TOKEN_ID`, `MUX_TOKEN_SECRET`, `FRONTEND_ORIGIN`, `REWARD_WEBHOOK_SECRET`, `MIN_RUNTIME_MINUTES=90`, `RUNTIME_TOLERANCE_MINUTES=3`.

The server needs FFprobe for real video-duration verification. Use a Render Docker deployment with FFmpeg/FFprobe installed if the selected runtime does not provide it.

## Database
Run `database/schema.sql` against PostgreSQL. Register the first account, then run:

`UPDATE users SET role='super_admin' WHERE email='YOUR_EMAIL';`

## Rules implemented
- TMDB metadata is fetched server-side.
- TMDB runtime must be at least 90 minutes.
- Uploaded runtime is measured with FFprobe.
- Uploaded runtime must match TMDB runtime within configured tolerance (default 3 minutes).
- Mux playback ID is required before publishing.
- First 24 hours after registration are free downloads.
- After that, one download consumes one download credit.
- One coin is intended to grant two download credits.
- One verified rewarded ad grants five download credits.
- Only `super_admin` can modify Trending.
- Coin/reward balances are backend controlled.
