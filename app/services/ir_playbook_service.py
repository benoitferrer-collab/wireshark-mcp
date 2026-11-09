"""Evidence-led support playbooks. Suggestions and checklists, never network actions."""
from copy import deepcopy
from datetime import datetime, timezone
from math import isfinite
from app.services.support_playbook_catalog import PLAYBOOK_TEMPLATES


class IRPlaybookGenerator:
    VERSION = 'nomios-v2'

    def catalog(self):
        return [{'id': key, 'name': value['name'], 'category': value['category'],
                 'description': value['description']} for key, value in PLAYBOOK_TEMPLATES.items()]

    @staticmethod
    def _number(value):
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and isfinite(value) and value >= 0 else 0

    def _recommendations(self, results):
        reasons = {}
        dns = results.get('dns_analysis', {}).get('summary', {})
        count = self._number(dns.get('nxdomain_count'))
        if count:
            reasons['dns_resolution'] = f'{count:g} réponse(s) NXDOMAIN observée(s) ; vérifier le lien avec le symptôme.'
        tcp = results.get('tcp_analysis', {})
        retrans = self._number(tcp.get('summary', {}).get('total_retransmissions'))
        if retrans:
            reasons['packet_loss'] = f'{retrans:g} retransmission(s) TCP observée(s) ; perte, réordonnancement ou artefact à départager.'
        rtt = self._number(tcp.get('rtt_analysis', {}).get('avg_rtt_ms'))
        if rtt >= 100:
            reasons['network_latency'] = f'RTT moyen mesuré : {rtt:g} ms ; repère de tri à 100 ms, à comparer à la référence du service.'
        flow = results.get('flow_behavior', {}).get('summary', {})
        for field, key in [('beaconing_alerts', 'c2_beaconing'), ('exfiltration_alerts', 'exfiltration')]:
            if self._number(flow.get(field)):
                reasons[key] = 'Indicateur calculé par le module de flux ; suspicion à confirmer avec le contexte client.'
        if self._number(results.get('lateral_movement', {}).get('summary', {}).get('total_indicators')):
            reasons['lateral_movement'] = 'Indicateur de mouvement latéral ; vérifier les usages administratifs autorisés.'
        kinds = {str(a.get('type', '')).upper() for a in results.get('all_anomalies', []) if isinstance(a, dict)}
        for kind, key in [('BRUTE_FORCE', 'brute_force'), ('PORT_SCAN', 'network_scan'), ('SYN_FLOOD', 'traffic_flood')]:
            if kind in kinds:
                reasons[key] = f'Indicateur {kind} du détecteur ; qualification requise, aucun incident confirmé automatiquement.'
        return reasons

    def generate(self, analysis_results, incident_types=None):
        reasons = self._recommendations(analysis_results)
        manual = incident_types is not None
        if manual:
            if not incident_types or len(incident_types) > len(PLAYBOOK_TEMPLATES) or any(key not in PLAYBOOK_TEMPLATES for key in incident_types):
                raise ValueError('Choisissez entre 1 et 14 parcours du catalogue.')
            selected = list(dict.fromkeys(incident_types))
        else:
            selected = list(reasons) or ['qualification']
        playbooks = []
        for key in selected:
            item = deepcopy(PLAYBOOK_TEMPLATES[key])
            item.update(incident_type=key, playbook_id=f'{self.VERSION}-{key}',
                        selection_basis='manual' if manual else 'observed_signal' if key in reasons else 'fallback',
                        selection_reason='Parcours choisi par l’ingénieur ; ce choix ne confirme pas un incident.' if manual else reasons.get(key, 'Aucun indicateur spécifique exploitable : commencer par qualifier le ticket.'),
                        total_tasks=sum(len(p['tasks']) for p in item['phases']), completed_tasks=0,
                        context_iocs=[], context='Checklist proposée pour le support Nomios, à adapter et valider selon le contrat et les procédures du client.')
            playbooks.append(item)
        return {'generated_at': datetime.now(timezone.utc).isoformat(), 'selection_mode': 'manual' if manual else 'suggested',
                'incident_types_detected': [], 'suggested_types': list(reasons), 'total_playbooks': len(playbooks), 'playbooks': playbooks}
