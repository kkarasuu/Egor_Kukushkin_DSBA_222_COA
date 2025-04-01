test-report:
	@TIMESTAMP=$$(date +"%Y-%m-%d_%H-%M-%S") && \
	docker compose run --rm user_service_tests pytest --html=/app/reports/report_$$TIMESTAMP.html --self-contained-html && \
	echo "Отчет сгенерирован: test_reports/report_$$TIMESTAMP.html" && \
	open test_reports/report_$$TIMESTAMP.html
