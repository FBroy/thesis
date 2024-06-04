import os
import json


def parse(path):
    files = os.listdir(path)
    allFinalInformation = []
    for name in files:
        with open(path + name) as f:
            data = json.load(f)

            # General
            """
            https://docs.virustotal.com/reference/files

            data
                attributes
                    capabilities_tags (premium only, not available)
                    creation_date (date of creation/compilation/build)
                    downloadable (boolean, not needed)
                    first_submission_date: timestamp of first submission (can be used for timeline)
                    last_analysis_date: timestamp (not needed)
                    last_analysis_results: Analysis object (https://docs.virustotal.com/reference/analyses-object) --> extracting score and other information
                    last_analysis_stats: (dictionary) a summary of the latest scan results
                    last_modification_date: timestamp (maybe useful?)
                    last_submission_date: timestamp (not needed)
                    main_icon: relevant hashes of the file
                        raw_md5
                        dhash
                    md5: md5 hash
                    meaningful_name: mostly just the name of the file, might be helpful to find the original file name
                    names: list of known names
                    reputation: score from community votes
                    sandbox_verdicts: summaries from all sandboxes (dictionary)
                        category
                        confidence
                        malware_classification
                        malware_names
                        sandbox_name
                    sha1: sha1 hash
                    sha256: sha256 hash
                    sigma_analysis_summary: all matches sigma rules (dictionary)
                    size: size of the file in bytes
                    tags: list of attributes
                    times_submitted: number of times file has been posted to Virustotal
                    total_votes: total votes from the community
                        harmless
                        malicious
                    type_description: describe the file type
                    type_extension: specifies the file extension
                    type_tag: tag representing the file type
                    type_tags: list of tags representing the file type on a broader scale
                    unique_sources: number of sources the file has been posted from
                    vhash: find similar files with this
                    crowdsourced_ai_results: ???
                    popular_threat_classification: (dictionary) suggested_threat_label = suggested_threat_category + popular_threat_name
                    detectiteasy: ??
                    sigma_analysis_results: check sigma_analysis_summary --> single results
                        analysis
                        source
                        id

                    packers: the packing that was used
                    pe_info: language, imports, entry_point, etc
                    first_seen_itw_date: first seen in the wild timestamp
                    tlsh
                    crowdsourced_yara_results
                        description
                        source
                        author
                        ruleset_name
                        rule_name
                        ruleset_id
                    authentihash
                    trid
                    ssdeep
                    magic

                id (sha256Hash)
                links (not needed)
                type (always file)
            """
            general = data[0]['data']['attributes']

            newGeneral = {}
            newGeneral['variant'] = general['last_analysis_results']['Microsoft']['result']
            newGeneral['creation_date'] = general.get('creation_date')
            newGeneral['file_information'] = general.get('detectiteasy')
            newGeneral['first_seen_itw'] = general.get('first_seen_itw_date')
            newGeneral['first_submission_date'] = general.get('first_submission_date')

            newGeneral['analysis_results'] = {}
            for key, value in general.get('last_analysis_results').items():
                newGeneral['analysis_results'][key] = {
                    'category': value['category'],
                    'result': value['result'],
                    'method': value['method']
                }

            newGeneral['analysis_stats'] = general.get('last_analysis_stats')
            newGeneral['hashes'] = {
                'md5': general.get('md5'),
                'sha1': general.get('sha1'),
                'sha256': general.get('sha256')
            }
            newGeneral['magic'] = general.get('magic')
            newGeneral['names'] = general.get('names')
            newGeneral['packers'] = general.get('packers')
            newGeneral['pe_info'] = general.get('pe_info')
            newGeneral['threat_classification'] = general.get('popular_threat_classification')

            newGeneral['sandbox_verdicts'] = {}
            for key, value in general.get('sandbox_verdicts', {}).items():
                newGeneral['sandbox_verdicts'][key] = {
                    'category': value['category'],
                    'malware_classification': value['malware_classification'],
                    'malware_names': value.get('malware_names')
                }

            newGeneral['sigma_rules'] = general.get('sigma_analysis_results')
            newGeneral['sigma_rules_stats'] = general.get('sigma_analysis_stats')
            newGeneral['size'] = general.get('size')
            newGeneral['file_tags'] = general.get('tags')
            newGeneral['file_type'] = general.get('trid')
            newGeneral['type'] = general.get('type_description')
            newGeneral['extension'] = general.get('type_extension')
            newGeneral['type_tags'] = general.get('type_tags')

            # Behaviour summary
            """
            https://docs.virustotal.com/reference/file-behaviour-summary

            data
                attack_techniques
                calls_highlighted: (list of strings) API calls/Syscalls worth highlighting
                command_executions: (list of strings) shell command executions observed during the analysis of the given file
                crypto_algorithms_observed: (list of strings) Example: RSA.
                crypto_keys: (list of strings) e.g. "MySecret".
                crypto_plain_text: (list of strings) strings that are either ciphered or deciphered during the observed time frame, we record just the plaintext.
                dns_lookups
                files_opened: (list of strings) files opened during execution
                files_written: (list of strings) files written during execution
                files_deleted: (list of strings) files deleted during execution
                files_dropped
                files_attributes_changed: (list of strings) full path of files subject to some sort of active attribute modification
                hosts_file: if the file was modified, contents are here, otherwise empty
                ids_alerts: (list of dictionaries) list of IDS alerts
                    alert_context
                        dest_ip
                        dest_port
                        hostname
                        protocol
                        src_ip
                        src_port
                        url
                    alert_severity
                    rule_category
                    rule_id
                    rule_msg
                    rule_source
                invokes: (list of strings) method/functionality called via reflection or some sort of runtime instantiation. The best example are Java reflection calls, in those cases we flatten the structure to a string: ..
                ja3_digests: (list of strings) JA3 fingerprinting of TLS client connections.
                mitre_attack_techniques (list of dictionaries)
                    signature_description
                    id
                    severity
                modules_loaded
                mutexes_opened: (list of strings) name of the mutexes for which the file acquires a handle
                mutexes_created: (list of strings) new mutexes created.
                processes_created: (list of strings)
                processes_terminated: (list of strings) name of the processes that were terminated during the execution of a given file
                processes_tree
                processes_killed: (list of strings) name of the processes that were killed during the execution of a given file
                processes_injected: (list of strings) name of the processes that were subjected to some kind of code injection during the execution of the given file
                registry_keys_set: (list of dictionaries)
                    key
                    value
                registry_keys_opened: (list of strings)
                services_opened: (list of strings) names of the services for which a handle was acquired during the analysis of the given file
                services_created: (list of strings) new services created
                services_started: (list of strings) new services started
                services_stopped: (list of strings) services stopped during the execution of the given file
                services_deleted: (list of strings) services deleted during the execution of the given file
                services_bound: (list of strings) service binding
                sigma_analysis_results: (list of dictionaries)
                    rule_title
                    rule_source
                    match_context
                        values
                    rule_level
                    rule_description
                    rule_author
                    rule_id
                signals_observed: (list of strings) OS Signals and broadcast events, note that Android broadcasts are categorized here also.
                signature_matches
                    format
                    authors
                    rule_src
                    name
                    description
                tags
                text_decoded: (list of strings) plaintext which is the result of a decoding operation.
                text_highlighted (list of strings) interesting text seen in window dialogs, titles, etc.
                tls: (list of dictionaries)
                    issuer
                    ja3
                    ja3s
                    serial_number
                    sni
                    subject
                    thumbprint
                    version
                verdicts
                verdict_labels
                verdict_confidence: (integer) 99 = 99% confident verdict is correct.
                windows_searched: (list of strings) names of windows that are searched for
                windows_hidden: (list of strings) names of windows that are set up to be invisible
                
                ~~Android specific fields~~
                activities_started: <list of strings> Android activities launched by the app under study.
                content_model_observers: <list of strings> content for which an Android app registers logic to be informed about any changes to it.
                content_model_sets: <list of dictionaries> content model entries performed by an Android app.
                databases_deleted: <list of strings> e.g. Android SQLite DBs deleted.
                databases_opened: <list of strings> interactions with databases, e.g. when an Android app opens an SQLite DB.
                permissions_requested: <list of strings> Android permissions requested by the app during runtime. In Windows it should also record process token privilege modifications such as SE_LOAD_DRIVER_PRIVILEGE.
                shared_preferences_lookups: <list of strings> entries in Android's shared preferences that are checked (https://developer.android.com/reference/android/content/SharedPreferences.html).
                shared_preferences_sets: <list of dictionaries> entries written in Android's shared preferences. Every subitem contains the following fields:
                    key: <string> preference name.
                    value: <string> set value.
                signals_hooked: <list of strings> registering a receiver in Android is considered as a broadcast hook. In windows this field will contain SetWindowsHookExA activity and the like.
                system_property_lookups: <list of strings> interactions with Android's system properties dataset (getInt, getString, putInt, putString, etc. all get simply translated into strings. android.os.SystemProperties.).
                system_property_sets: <list of dictionaries> keys and values set in Android's system properties dataset.
                ~~End Android specific fields~~
                
                ~~Windows specific fields~~
                modules_loaded (list of strings)
                registry_keys_opened (list of strings)
                registry_keys_set (list of dictionaries)
                    key
                    value
                registry_keys_deleted (list of strings)
                ~~End Windows specific fields~~
                
                NOT analysis_date, NOT behash, NOT has_html_report, NOT has_pcap, NOT last_modification_date, NOT sandbox_name
            """
            # behaviourSummaryAll = ['activities_started', 'attack_techniques', 'calls_highlighted', 'command_executions', 'content_model_observers', 'content_model_sets', 'crypto_algorithms_observed', 'crypto_keys', 'crypto_plain_text', 'databases_deleted', 'databases_opened', 'dns_lookups', 'files_attributes_changed', 'files_deleted', 'files_dropped', 'files_opened', 'files_written', 'hosts_file', 'ids_alerts', 'invokes', 'ja3_digests', 'mitre_attack_techniques', 'modules_loaded', 'mutexes_created', 'mutexes_opened', 'permissions_requested', 'processes_created', 'processes_injected', 'processes_killed', 'processes_terminated', 'processes_tree', 'registry_keys_deleted', 'registry_keys_opened', 'registry_keys_set', 'services_bound', 'services_created', 'services_deleted', 'services_opened', 'services_started', 'services_stopped', 'shared_preferences_lookups', 'shared_preferences_sets', 'sigma_analysis_results', 'signals_hooked', 'signals_observed', 'signature_matches', 'system_property_lookups', 'system_property_sets', 'tags', 'text_decoded', 'text_highlighted', 'tls', 'verdict_confidence', 'verdict_labels', 'verdicts', 'windows_hidden', 'windows_searched']
            # behaviourSummaryUsed = ['attack_techniques', 'calls_highlighted', 'command_executions', 'crypto_algorithms_observed', 'dns_lookups', 'files_attributes_changed', 'files_deleted', 'files_dropped', 'files_opened', 'files_written', 'hosts_file', 'ids_alerts', 'ip_traffic', 'mitre_attack_techniques', 'modules_loaded', 'mutexes_created', 'mutexes_opened', 'processes_created', 'processes_injected', 'processes_killed', 'processes_terminated', 'processes_tree', 'registry_keys_deleted', 'registry_keys_opened', 'registry_keys_set', 'services_bound', 'services_created', 'services_deleted', 'services_opened', 'services_started', 'services_stopped', 'signals_observed', 'signature_matches', 'tags', 'text_decoded', 'text_highlighted', 'windows_hidden', 'windows_searched']
            # behaviourSummaryUnused = ['activities_started', 'content_model_observers', 'content_model_sets', 'crypto_keys', 'crypto_plain_text', 'databases_deleted', 'databases_opened', 'invokes', 'ja3_digests', 'permissions_requested', 'sigma_analysis_results', 'shared_preferences_lookups', 'shared_preferences_sets', 'signals_hooked', 'system_property_lookups', 'system_property_sets', 'tls', 'verdict_confidence', 'verdict_labels', 'verdicts']
            behaviourSummary = data[1]['data']
            if behaviourSummary:
                newBehaviour = {}
                newBehaviour['attack_techniques'] = behaviourSummary.get('attack_techniques')
                newBehaviour['calls_highlighted'] = behaviourSummary.get('calls_highlighted')
                newBehaviour['command_executions'] = behaviourSummary.get('command_executions')
                newBehaviour['crypto_algorithms_observed'] = behaviourSummary.get('crypto_algorithms_observed')
                newBehaviour['dns_lookups'] = behaviourSummary.get('dns_lookups')
                newBehaviour['files'] = {}
                newBehaviour['files']['deleted'] = behaviourSummary.get('files_deleted')
                newBehaviour['files']['dropped'] = behaviourSummary.get('files_dropped')
                newBehaviour['files']['opened'] = behaviourSummary.get('files_opened')
                newBehaviour['files']['written'] = behaviourSummary.get('files_written')
                newBehaviour['files_attributes_changed'] = behaviourSummary.get('files_attributes_changed')
                newBehaviour['ids_alerts'] = behaviourSummary.get('ids_alerts')
                newBehaviour['ip_traffic'] = behaviourSummary.get('ip_traffic')
                newBehaviour['hosts_file'] = behaviourSummary.get('hosts_file')
                newBehaviour['mitre_attack_techniques'] = {}
                for value in behaviourSummary.get('mitre_attack_techniques', []):
                    newBehaviour['mitre_attack_techniques'][value['id']] = {
                        'signature_description': value.get('signature_description', "No description available"),
                        'severity': value.get('severity', "IMPACT_SEVERITY_UNKNOWN")
                    }
                newBehaviour['modules_loaded'] = behaviourSummary.get('modules_loaded')
                newBehaviour['mutexes'] = {}
                newBehaviour['mutexes']['created'] = behaviourSummary.get('mutexes_created')
                newBehaviour['mutexes']['opened'] = behaviourSummary.get('mutexes_opened')
                newBehaviour['processes'] = {}
                newBehaviour['processes']['created'] = behaviourSummary.get('processes_created')
                newBehaviour['processes']['injected'] = behaviourSummary.get('processes_injected')
                newBehaviour['processes']['killed'] = behaviourSummary.get('processes_killed')
                newBehaviour['processes']['terminated'] = behaviourSummary.get('processes_terminated')
                newBehaviour['processes']['tree'] = behaviourSummary.get('processes_tree')
                newBehaviour['registry_keys'] = {}
                newBehaviour['registry_keys']['deleted'] = behaviourSummary.get('registry_keys_deleted')
                newBehaviour['registry_keys']['opened'] = behaviourSummary.get('registry_keys_opened')
                newBehaviour['registry_keys']['set'] = behaviourSummary.get('registry_keys_set')
                newBehaviour['signature_matches'] = {}
                for value in behaviourSummary.get('signature_matches', []):
                    newBehaviour['signature_matches'][value.get('name', "No name")] = value.get('description')
                newBehaviour['tags'] = behaviourSummary.get('tags')
                newBehaviour['verdicts'] = behaviourSummary.get('verdicts')
                newBehaviour['services'] = {}
                newBehaviour['services']['bound'] = behaviourSummary.get('services_bound')
                newBehaviour['services']['created'] = behaviourSummary.get('services_created')
                newBehaviour['services']['deleted'] = behaviourSummary.get('services_deleted')
                newBehaviour['services']['opened'] = behaviourSummary.get('services_opened')
                newBehaviour['services']['stopped'] = behaviourSummary.get('services_stopped')
                newBehaviour['services']['started'] = behaviourSummary.get('services_started')
                newBehaviour['signals_observed'] = behaviourSummary.get('signals_observed')
                newBehaviour['text_decoded'] = behaviourSummary.get('text_decoded')
                newBehaviour['text_highlighted'] = behaviourSummary.get('text_highlighted')
                newBehaviour['windows_hidden'] = behaviourSummary.get('windows_hidden')
                newBehaviour['windows_searched'] = behaviourSummary.get('windows_searched')

            # MITRE
            """
            data
                sandbox_name
                    tactics (list)
                        id
                        name
                        description
                        link
                        techniques (list)
                            id
                            name
                            description
                            link
                            signatures (list)
                                severity
                                description
            links
            """
            mitre = {}
            mitre['sandboxes'] = data[2]['data']

            finalInformation = {}
            for key, value in newGeneral.items():
                finalInformation[key] = value
            for key, value in newBehaviour.items():
                finalInformation[key] = value
            for key, value in mitre.items():
                finalInformation[key] = value

            allFinalInformation.append(finalInformation)
    return allFinalInformation