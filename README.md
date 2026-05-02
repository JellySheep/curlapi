# Запуск контейнеров в фоновом режиме
docker compose up -d

# Сбор данных об уязвимостях 
docker compose exec app python3 collector.py

# Конвертация данных в XML формат
docker compose exec app python3 converter.py

# Валидация JSON по заданной схеме
docker compose exec app python3 validate_task.py

# Загрузка обработанных данных в базу данных PostgreSQL
docker compose exec app python3 db_filler.py
