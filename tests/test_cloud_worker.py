from types import SimpleNamespace
from app.cloud.worker import handle_delivery
from app.cloud.jobs import JobService
from tests.test_cloud import Objects

class Process:
    returncode = 1

def test_completed_and_deleted_jobs_do_not_start_process():
    objects = Objects()
    jobs = JobService(objects)
    jobs.status('done', 'completed', 100, 'Done')
    def forbidden(*a, **k): raise AssertionError('process started')
    assert handle_delivery('done', 1, objects, runner=forbidden) is True
    objects.write_json('deleted/gone.json', {'deleted': True})
    assert handle_delivery('gone', 1, objects, runner=forbidden) is True

def test_failed_subprocess_retries_then_reaches_failed_status():
    objects = Objects()
    assert handle_delivery('abc', 1, objects, runner=lambda *a, **k: Process()) is False
    assert JobService(objects).read_status('abc')['status'] == 'processing'
    assert handle_delivery('abc', 3, objects, runner=lambda *a, **k: Process()) is True
    assert JobService(objects).read_status('abc')['status'] == 'failed'
