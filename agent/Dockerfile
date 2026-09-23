# adhealth-agent container image (for ECS/Fargate scheduled tasks, Bedrock AgentCore Runtime, or any container host).
# Non-root, no secrets baked in: credentials come from the task role / IAM Roles Anywhere; webhooks and Graph
# settings come from environment variables injected by the platform (e.g. Secrets Manager -> ECS secrets).
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml ./
COPY adhealth_agent ./adhealth_agent
RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /wheels ".[llm,graph]"

FROM python:3.12-slim
RUN groupadd --system --gid 10001 adhealth \
 && useradd --system --uid 10001 --gid adhealth --home-dir /var/lib/adhealth --create-home adhealth
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels "adhealth-agent[llm,graph]" && rm -rf /wheels
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /var/lib/adhealth
# Mount: /etc/adhealth (settings.yaml + policy.yaml, read-only), /var/lib/adhealth/state (persistent), inbox (read-only)
ENTRYPOINT ["adhealth-agent", "--log-format", "json"]
CMD ["--help"]
