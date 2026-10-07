from celery import Celery


celery_app = Celery(

    "rag_chatbot",

    broker="redis://localhost:6379/0",

    backend="redis://localhost:6379/1",

    include=["task"],
)


celery_app.conf.update(

    # Task serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Show STARTED state for running tasks
    task_track_started=True,
)