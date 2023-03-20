Welcome to the prototype implementation of the Semaphore sequencer and client

Requires Python3.10 environment with plyvel, ecdsa, and PyQt5 installed
Pip has trouble installing plyvel, so a conda environment is recommented
If you do not already have anaconda installed, you can download miniconda here: https://docs.conda.io/en/latest/miniconda.html
You can build the conda environment by running 'conda env create -f environment.yml' or by following the instructions in requirements.txt

To run the sequencer, run sequencer/node.py
To run the client, run client/node.py

By default the sequencer will run on localhost on port 5000
To change the defaults, edit params.json
The sequencer private key is set by default. To change the private key, delete sequencer_db and it will atomatically reset on startup
SEQUENCER_PUBKEY must be updated in params.json if the sequencer private key is updated
Use the "pubkey" command to get the sequencer pubkey

The client will automatically connect to the sequencer on startup

In the GUI:
Write a message then click the "broadcast" button to broadcast
Click on a previous message to reply
Broadcast "!mint" to mint a new alias
Broadcast "!nym <your_new_nym>" to update your alias nym

In the Terminal:
Use the "mint" command to create reqeust a new alias
Use the "key" command to update the alias' pubkey/privkey
Use the "nym" command to update the alias' human-readable screen NamedTuple
Use the "bc" command to send a broadcast

Use the "toggle_show" command to toggle if new broadcasts are printed for both sequencer and client
Enabled by default for client
Disable by default for sequencer

Watch out for bugs!
