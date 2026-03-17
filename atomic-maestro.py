import argparse
import json
import csv
from pathlib import Path

print(r'''
    ___   __                  _          __  ___                 __           
   /   | / /_____  ____ ___  (_)____    /  |/  /____  ___  _____/ /__________ 
  / /| |/ __/ __ \/ __ `__ \/ / ___/   / /|_/ / __ `/ _ \/ ___/ __/ ___/ __ \
 / ___ / /_/ /_/ / / / / / / / /__    / /  / / /_/ /  __(__  ) /_/ /  / /_/ /
/_/  |_\__/\____/_/ /_/ /_/_/\___/   /_/  /_/\__,_/\___/____/\__/_/   \____/ 
                                                                             
[ Automated MITRE ATT&CK® Navigator Emulation Plan Generator for Red Canary's Atomic Red Team ]
''')

mitre_tactics_indices = {'reconnaissance': 1, 'resource-development': 2, 'initial-access': 3, 'execution': 4, 'persistence': 5, 'privilege-escalation': 6, 'defense-evasion': 7, 'credential-access': 8, 'discovery': 9, 'lateral-movement': 10, 'collection':11 , 'command-and-control': 12, 'exfiltration': 13, 'impact': 14}

argparser = argparse.ArgumentParser()

argparser.add_argument('--mitre-filepath', type=str, required=True, help='MITRE ATT&CK® Navigator JSON file path')
argparser.add_argument('--source-filepath', type=str, default=str(Path.home() / 'AtomicRunner' / 'AtomicRunnerSchedule.csv'), help='Atomic Red Team Source Schedule CSV file path')
argparser.add_argument('--destination-filepath', type=str, default=str(Path.home() / 'AtomicRunner' / 'atomic_schedule.csv'), help='Atomic Red Team built destination Schedule CSV file path')
argparser.add_argument('--timeout-seconds', type=int, default=60, help='Maximum execution time in seconds for an atomic test')
argparser.add_argument('--supported-platforms', type=str, nargs='*', help='Filter techniques by one or more supported platforms (platforms should be provided separated by spaces and following Atomic Red Team CSV Schedule "supported_platforms" syntax). Example: --supported-platforms windows azure-ad office-365 iaas:azure')

args = argparser.parse_args()

with open(args.mitre_filepath, 'r', encoding='UTF-8') as file:
    mitre_data = json.load(file)

enabled_techniques = [
    technique for technique in mitre_data.get('techniques', [])
    if technique.get('score') == 1
]

enabled_techniques.sort(key=lambda x: mitre_tactics_indices.get(x.get('tactic'), 99))

technique_map = {technique['techniqueID']: [] for technique in enabled_techniques}

with open(args.source_filepath, 'r', encoding='UTF-8') as file:
    art_schedule_csv = csv.DictReader(file)
    for row in art_schedule_csv:
        id_csv = row['Technique']
        if id_csv in technique_map:
            technique_map[id_csv].append(row)

schedule_csv_fieldnames = ['Order','Technique','TestName','auto_generated_guid','supported_platforms','TimeoutSeconds','InputArgs','AtomicsFolder','enabled','notes']

with open(args.destination_filepath, 'w', encoding='UTF-8', newline='') as file:
    schedule_csv = csv.DictWriter(file, fieldnames=schedule_csv_fieldnames)
    schedule_csv.writeheader()

    for technique in enabled_techniques:
        for atomic_test in technique_map.get(technique['techniqueID'], []):
            if args.supported_platforms:
                atomic_test_supported_platforms = set(atomic_test['supported_platforms'].strip().lower().split('|'))
                prepared_args = {arg.strip().lower() for arg in args.supported_platforms}
                if atomic_test_supported_platforms.isdisjoint(prepared_args):
                    continue
            atomic_test['TimeoutSeconds'] = args.timeout_seconds
            atomic_test['enabled'] = True
            schedule_csv.writerow(atomic_test)

print('\n****************************************************************************************************')
print('Schedule CSV file generated in ', args.destination_filepath)
print('****************************************************************************************************\n')
