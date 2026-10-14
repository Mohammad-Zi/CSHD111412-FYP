# CSHD111412-FYP
Final year project for Higher Diploma


# IMPORTANT FOR CHECKING ERRIRS
python -m py_compile .\gui.py
python -m py_compile .\database.py
python -m py_compile .\run_audit.py
python .\main.py

# WSL Requirements
sudo visudo 

# Put at the very end of the file
<vm_user> ALL=(ALL) NOPASSWD: ALL

# test command in WSL
ansible <VM-IP> -i inventory -m shell -a "whoami" --become

sudo -k && sudo whoami

sudo chmod 440 /etc/sudoers.d/<enter-username>


# SQL COMMANDS
UPDATE cis_commands
SET requires_root = 1 
WHERE command_id = '8';

UPDATE cis_commands
SET requires_root = 1 
WHERE command_id = '17';



