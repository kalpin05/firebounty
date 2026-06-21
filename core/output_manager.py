import os

DIRECTORIES = [

    "outputs/recon",
    "outputs/endpoints",
    "outputs/findings",
    "outputs/reports"
]

def create_output_dirs():

    for d in DIRECTORIES:

        os.makedirs(d, exist_ok=True)