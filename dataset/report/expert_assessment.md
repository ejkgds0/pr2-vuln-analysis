# Экспертная оценка безопасности

## Сводка найденных уязвимостей

| Проект | Тип | CWE | OWASP | CVSS | Критичность |
|---|---|---|---|---|---|
| vulnerable.py | Hardcoded Credentials | CWE-798 | A07 | - | Low |
| vulnerable.py | SQL Injection | CWE-89 | A03 | 9.8 | Critical |
| vulnerable.py | Reflected XSS | CWE-79 | A03 | - | High |
| vulnerable.py | OS Command Injection | CWE-78 | A03 | 9.8 | Critical |
| vulnerable.py | Code Injection (eval) | CWE-95 | A03 | - | High |
| vulnerable.py | Insecure Deserialization | CWE-502 | A08 | 9.8 | Critical |
| vulnerable.py | Path Traversal | CWE-22 | A01 | 7.5 | High |
| vulnerable.py | Weak Hash (MD5) | CWE-327 | A02 | - | Medium |
| vulnerable.py | Debug Mode Enabled | CWE-489 | A05 | - | High |
| VulnMart | Hardcoded Password | CWE-259 | A07 | - | Low |
| VulnMart | SQL Injection | CWE-89 | A03 | 9.8 | Critical |
| VulnMart | Missing CSRF Protection | CWE-352 | A01 | - | Medium |

## Методология
Анализ проведён в два этапа. Статический анализ (SAST) выполнен сканерами
Bandit и Semgrep на двух проектах: собственном vulnerable.py (9 намеренно заложенных уязвимостей) и готовом учебном приложении VulnMart.
Динамический анализ (DAST) выполнен вручную через curl-запросы к запущенному vulnerable.py и подтвердил эксплуатируемость 5 из 9 уязвимостей на практике.

## Ключевые выводы

1. **Ни один сканер не находит всё.** Bandit обнаружил 7 из 9 уязвимостей
   vulnerable.py, Semgrep 8 из 9, но пропущенные классы (XSS у Bandit,
   секреты в коде у Semgrep) у инструментов разные. Вместе они покрыли
   все 9, что подтверждает необходимость использования нескольких SAST-
   инструментов одновременно.

2. **Статический анализ не видит логических уязвимостей.** В VulnMart
   Bandit нашёл только 2 проблемы из заявленных в документации четырёх
   классов (SQL-инъекция, XSS, IDOR, слабая аутентификация) - хранимая
   XSS и IDOR находятся в шаблонах и логике доступа, которые требуют
   либо более специализированных правил (Semgrep нашёл проблему с CSRF,
   которую Bandit не видит в принципе), либо прогона приложения (DAST).

3. **Уязвимости усиливают друг друга.** Path Traversal (CWE-22) позволил
   прочитать исходный код приложения и тем самым раскрыл Hardcoded
   Credentials (CWE-798) - пароль администратора. По отдельности каждая
   уязвимость оценивается ниже, чем их совместный эффект.

4. **SQL Injection и OS Command Injection - самые опасные находки**
   (CVSS 9.8), обе относятся к OWASP A03 Injection и имеют прямые реальные
   аналоги в базе CVE (CVE-2020-37243, CVE-2025-59377).

## Рекомендации

1. Все SQL-запросы переписать на параметризованные (`db.execute(query, (params,))`).
2. Отключить `debug=True` и привязку к `0.0.0.0` в продакшене.
3. Заменить `pickle` на `json` или подписывать сериализованные данные (HMAC).
4. Экранировать пользовательский ввод при выводе в HTML (`markupsafe.escape`).
5. Заменить `shell=True` на список аргументов с `shell=False`.
6. Убрать `eval()`, при необходимости вычислений использовать `ast.literal_eval()`.
7. Санитизировать имена файлов через `werkzeug.utils.secure_filename()`.
8. Вынести все секреты в переменные окружения.
9. Заменить MD5 на `bcrypt` или `argon2` для хеширования паролей.
10. Добавить CSRF-токены во все формы, изменяющие состояние (Flask-WTF).

## Итоговая оценка риска
Уровень риска обоих проектов: **критический**. Обнаружено 3 уязвимости
с CVSS 9.8 (SQL Injection, OS Command Injection, Insecure Deserialization),
каждая из которых в реальном продакшене привела бы к полной компрометации
сервера. Оба проекта непригодны для развёртывания без устранения найденных
проблем.
