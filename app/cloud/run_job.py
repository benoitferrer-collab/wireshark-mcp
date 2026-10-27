"""Process one persisted manifest; no request or queue state is kept in RAM between jobs."""
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import shutil
from .context import scratch
from .jobs import valid_id, validate_capture, MAX_FILE, JobService


def execute(task_id):
    from app.services.storage_service import storage_service as storage
    from app.services.pcap_service import PCAPAnalysisService
    task_id = valid_id(task_id)
    objects = storage.objects
    jobs = JobService(objects)
    if storage.deleted(task_id): return
    job = objects.read_json(f'jobs/{task_id}.json')
    if not job: raise ValueError('Missing analysis manifest')
    root = Path(tempfile.mkdtemp(prefix='pcap-worker-'))
    marker = scratch.set(root)
    try:
        paths = []
        for capture in job['captures']:
            pathname = validate_capture(task_id, capture)
            path = storage.get_upload_path(task_id, Path(pathname).name)
            objects.download(pathname, path, max_size=MAX_FILE)
            if not storage.validate_pcap_file(path): raise ValueError('Invalid PCAP magic or size')
            paths.append(path)
        if job['kind'] == 'single':
            results = PCAPAnalysisService().analyze(paths[0], job['captures'][0]['filename'], enable_enrichment=False)
            storage.save_results(task_id, results)
        else:
            from app.services.multi_pcap_service import MultiPcapAnalysisService, CaptureInput
            captures = [CaptureInput(file_path=path, filename=item['filename'],
                        equipment_name=item['equipment_name'], position=item['position'], comment=item['comment'])
                        for item, path in zip(job['captures'], paths)]
            analysis = MultiPcapAnalysisService().analyze(captures, **job['options'])
            storage.save_multi(task_id, {'task_id': task_id, 'status': 'completed',
                'generated_at': datetime.now(timezone.utc).isoformat(), 'analysis': analysis})
        jobs.status(task_id, 'completed', 100, 'Analyse terminée')
    finally:
        scratch.reset(marker)
        shutil.rmtree(root, ignore_errors=True)

if __name__ == '__main__': execute(sys.argv[1])
