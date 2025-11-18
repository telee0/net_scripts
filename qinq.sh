#!/bin/bash

path_script="/home/terence/poc"

cd $path_script
. /home/terence/miniconda3/etc/profile.d/conda.sh
conda activate poc
python qinq.py
conda deactivate
