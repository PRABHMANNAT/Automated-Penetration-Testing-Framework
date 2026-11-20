# AutoTest Research Workbench

AutoTest is a local research demonstration for the supplied automated web application security testing paper. The interface walks through scope authorization, recorded scanner evidence, result processing, triage, reporting, and the paper’s evaluation. It uses fictional `.test` assets and documentation-only IP addresses.

## Run on Windows

From this directory with Node.js 22 or newer and Python 3.10 or newer, run:

```powershell
npm ci
npm run build
python -m pip install -r requirements.txt
python -m uvicorn server:app --host 127.0.0.1 --port 8765
```

Open [the workbench](http://127.0.0.1:8765/) and select **Open demo workspace**. The seeded administrator can approve fixture authorizations. Account registration creates a Security Analyst and issues a local password recovery code. The demo account and records are shared within the local instance.

The downloadable archive includes the built interface. For that archive, start with the Python commands.

## Deploy to Vercel

1. Import the GitHub repository into Vercel. Use the repository root and the **FastAPI** preset. The checked-in configuration builds the React interface and packages it with the FastAPI application. [FastAPI on Vercel](https://vercel.com/docs/frameworks/backend/fastapi)
2. Set these environment variables for the Preview or Production environment you plan to deploy.

   | Variable | Value |
   | --- | --- |
   | `AUTOTEST_DATABASE_URL` | A PostgreSQL connection string for a dedicated demo database. Use the provider’s TLS connection string and a role that can create tables and triggers in the database schema. |
   | `AUTOTEST_DEMO_PASSWORD` | A unique demo password of 16–128 characters. |
   | `AUTOTEST_HOSTED` | Set to `1` if Vercel system environment variables are disabled. |

   Save the database URL and password as secrets. [Vercel environment variables](https://vercel.com/docs/environment-variables)
3. Deploy, then sign in as `demo@autotest.test` with the configured password and select **Auto-run demo**.

The hosted app stores replay history and sessions in PostgreSQL. Its shared demo account is password-protected. Local analyst registration and password recovery are available on localhost.

## Demonstration

Select **Auto-run demo** on **Overview**. The on-screen cursor checks scope, starts a recorded Storefront replay, walks through its evidence, records a sample review decision on the new replay, opens the report and research chart, and returns to the updated overview. The demo controls can pause or stop the walkthrough.

For a manual demonstration:

1. Open **Replay** and choose **Scope check**. Validate the prefilled URL, then change its port to `8443` and validate again to see the recorded rejection.
2. Open **Setup**, keep the default approved fixture, and select **Start replay**. **Monitor** shows the pipeline advance.
3. In **Pipeline**, compare 11 raw observations, 8 deduplicated findings, and 2 observations held by the classifier in the full Storefront fixture.
4. Open **Results** for the findings, review queue, and risk ranking. Export PDF or HTML under **Report**.
5. Use **Overview → Workspace records** for previous replays, authorizations, and the audit log. Open **Research** for the paper’s benchmark comparison.

The Nmap, OWASP ZAP, Nikto, and Nuclei screens use fixed recorded examples. Model probabilities and verification outcomes are fixture values. The app runs scope checks, performs schema mapping and deduplication, applies the probability filter, and calculates the paper’s composite score. Replays send zero requests to the assets. The recorded scanner error profile demonstrates a timeout outcome without executing an adapter.

## Storage and paper references

FastAPI defaults to SQLite at `.data/workspace.sqlite` on localhost. Set `AUTOTEST_DB` to choose another local file, or set `AUTOTEST_DATABASE_URL` to use a PostgreSQL instance. The server creates its tables and inserts the fixture records on first start.

The app’s normalization and grouping follow Section III-B. Risk weights, bands, and the false-positive cutoff follow Sections III-D and III-E. The evaluation view transcribes Tables III and IV and Section IV-D. The benchmark values are separate from local fixture results.
