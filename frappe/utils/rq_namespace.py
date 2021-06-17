from rq import Worker
from rq.job import Job

class JobBenchNamespace(Job):
	redis_job_namespace_prefix = 'rq:job:my-bench:my-site'

class JobSiteNamespace(Job):
	redis_job_namespace_prefix = 'rq:job:my-bench:'

class WorkerNamespace(Worker):
	job_class = JobBenchNamespace
