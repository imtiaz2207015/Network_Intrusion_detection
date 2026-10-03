# Network_Intrusion_detection
network intrusion detetcion system is a System dvelopment project courses lab project

## Dataset
Download CICIDS2017 (MachineLearningCVE CSVs) from https://www.unb.ca/cic/datasets/ids-2017.html and place them in a MachineLearningCVE/ folder.

## Setup
Create `nids-platform/.env` (it is gitignored) with a secret of your own:

    JWT_SECRET=your-random-string-here

Generate one with: `python -c "import secrets; print(secrets.token_hex(32))"`

Then run `docker compose up --build` inside `nids-platform/`.
