# SecureEmployeeAPI

## 1. Prezentarea proiectului

SecureEmployeeAPI este o aplicație demonstrativă realizată pentru disciplina „Ingineria aplicațiilor web”, în cadrul temei „Securitate și Date Sensibile”. API-ul gestionează fișe de angajați și ilustrează autentificarea, autorizarea operațiilor și protejarea informațiilor sensibile.

Fundamentul teoretic este capitolul 8, „Designing a secure API”, din cartea *The Design of Web APIs*, de Arnaud Lauret, Manning, 2019. Proiectul aplică aceste concepte prin separarea permisiunilor, verificarea accesului la fiecare resursă și limitarea informațiilor returnate. Referința bibliografică este disponibilă la [Manning](https://www.manning.com/books/the-design-of-web-apis).

Aplicația poate fi demonstrată folosind Swagger UI, fără un frontend separat sau o bază de date. Scopul este observarea unor mecanisme de securitate verificabile într-un cadru academic.

## 2. Tehnologii utilizate

Versiunile dependențelor directe sunt fixate în [requirements.txt](requirements.txt).

| Tehnologie | Rol în proiect |
|---|---|
| Python | Limbajul aplicației și al testelor; mediul verificat folosește Python 3.13.9. |
| FastAPI | Rutare HTTP, dependențe de securitate, documentație OpenAPI și Swagger UI. |
| Pydantic | Validarea cererilor și definirea câmpurilor expuse în răspunsuri. |
| PyJWT | Semnarea și validarea tokenurilor JWT. |
| pwdlib cu extra-ul `argon2` | Calcularea și verificarea hash-urilor parolelor prin Argon2. |
| Uvicorn | Server ASGI pentru rularea locală. |
| python-dotenv | Încărcarea configurației din fișierul local de mediu. |
| python-multipart | Procesarea formularului de autentificare. |
| pytest | Organizarea și executarea testelor automate. |
| httpx2 | Clientul HTTP folosit de `TestClient` în versiunea FastAPI/Starlette verificată. |
| `logging`, `json`, `datetime` | Module standard Python utilizate pentru audit; nu necesită instalare separată. |

## 3. Structura proiectului

```text
SecureEmployeeAPI/
├── app/
│   ├── _init_.py
│   ├── main.py
│   ├── security.py
│   ├── dependencies.py
│   ├── users.py
│   ├── schemas.py
│   ├── data.py
│   └── audit.py
├── tests/
│   ├── conftest.py
│   ├── test_auth_access.py
│   ├── test_crud_sensitive.py
│   ├── test_audit.py
│   └── test_error_security.py
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

| Modul | Responsabilitate |
|---|---|
| `app/main.py` | Instanța FastAPI, endpointurile, verificările de rol și handlerul pentru erorile de validare. |
| `app/security.py` | Încărcarea configurației, hashing-ul parolelor și emiterea JWT-urilor. |
| `app/dependencies.py` | Extragerea tokenului Bearer, validarea sa și verificarea scope-urilor. |
| `app/users.py` | Registrul conturilor demonstrative și verificarea credențialelor. |
| `app/schemas.py` | Modelele pentru date publice, date sensibile, creare/modificare și răspunsul de autentificare. |
| `app/data.py` | Datele inițiale ale angajaților, păstrate într-un dicționar în memorie. |
| `app/audit.py` | Loggerul dedicat și serializarea evenimentelor de succes. |
| `app/_init_.py` | Fișier gol existent în proiect; nu conține logică de inițializare. |
| `tests/conftest.py` | Configurație fictivă de test, fixture-uri și restaurarea stării. |

## 4. Funcționalități implementate

### Autentificare JWT

`POST /token` primește `username` și `password` ca formular, nu ca obiect JSON. Credențialele sunt verificate față de registrul demonstrativ. Parolele configurate sunt transformate în hash-uri la încărcarea conturilor; verificarea utilizatorilor inexistenți folosește și ea un hash demonstrativ pentru comparație.

La autentificare reușită, răspunsul conține `access_token` și `token_type`, acesta din urmă având valoarea `bearer`. Tokenul este semnat cu HS256 și expiră după 30 de minute. Payload-ul conține:

- `sub`: numele contului, utilizat pentru regăsirea sa în registru;
- `scopes`: permisiunile configurate pentru cont;
- `exp`: momentul expirării.

JWT-ul este semnat, nu criptat. Payload-ul nu conține parola, salariul sau telefonul. La cererile protejate se verifică semnătura, expirarea, identificatorul contului și scope-urile cerute. Rolul și asocierea cu angajatul sunt citite din registrul de conturi.

### Operații CRUD și controlul resurselor

Utilizatorii HR pot citi fișele publice. Contul de angajat poate consulta doar fișa asociată propriului `employee_id`. Crearea, modificarea și ștergerea necesită atât scope-ul de scriere, cât și rolul `hr_admin`.

POST atribuie un ID nou. PUT înlocuiește toate câmpurile editabile, păstrând ID-ul; nu este o actualizare parțială. DELETE elimină fișa și răspunde fără corp. Aceste operații gestionează fișe de angajați, nu conturi de autentificare.

### Separarea datelor publice de cele sensibile

| Model | Câmpuri |
|---|---|
| `EmployeePublic` | `id`, `full_name`, `department`, `position` |
| `EmployeeSensitive` | `id`, `phone`, `salary` |
| `EmployeeCreate` | `full_name`, `department`, `position`, `phone`, `salary` |

GET-urile obișnuite și răspunsurile POST/PUT folosesc `EmployeePublic`. Telefonul și salariul pot fi citite prin endpointul sensibil numai de un administrator autorizat.

Pentru POST și PUT, toate cele cinci câmpuri ale `EmployeeCreate` sunt obligatorii. Numele, departamentul și funcția au între 2 și 100 de caractere; telefonul are între 5 și 30 de caractere; salariul este numeric și strict pozitiv. Nu există o validare suplimentară a formatului telefonului.

### Audit

Operațiile reușite selectate produc evenimentele `employee.create`, `employee.update`, `employee.delete` și `employee.read_sensitive`. Fiecare mesaj JSON conține `timestamp` în UTC, `actor`, `operation`, `employee_id` și `result`, cu valoarea `success`.

Mesajele sunt trimise în terminal, printr-un handler dedicat al loggerului `secure_employee_api.audit`, fără propagare către loggerul global. Auditul este apelat după modificarea datelor sau după pregătirea datelor sensibile citite. Nu înregistrează parole, hash-uri, JWT-uri, chei, salarii, telefoane sau corpuri complete de cereri/răspunsuri.

### Mesaje de eroare

| Cod | Semnificație în aplicație |
|---|---|
| 401 | Token absent, invalid, expirat ori asociat unui cont inexistent; sau credențiale incorecte la autentificare. |
| 403 | Cont autentificat, dar scope insuficient, rol neautorizat ori acces interzis la fișa altui angajat. |
| 404 | Fișă inexistentă, după verificarea dreptului de acces. |
| 422 | Parametri, formular sau corp al cererii care nu respectă validarea. |
| 500 | Eroare internă; răspunsul implicit este `Internal Server Error`, fără traceback, în configurația actuală cu debug dezactivat. |

Pentru erorile 422, handlerul păstrează numai `loc`, `msg` și `type` pentru fiecare problemă. Valorile respinse (`input`) și contextul brut (`ctx`) nu sunt trimise clientului. Pentru accesul neautorizat la un ID de angajat, verificarea permisiunilor precedă căutarea fișei, astfel încât eroarea nu indică dacă aceasta există.

## 5. Roluri și permisiuni

Un **rol** reprezintă categoria utilizatorului și este verificat în endpoint. Un **scope** reprezintă o permisiune cerută de endpoint prin `Security`. Scope-ul trebuie să existe atât în JWT, cât și în permisiunile curente ale contului. Deținerea lui nu elimină verificarea rolului sau a proprietății resursei.

| Scope | Operații asociate |
|---|---|
| `employees:read` | Citirea listei și a fișelor publice, cu restricțiile de rol și ID. |
| `employees:write` | Crearea, înlocuirea și ștergerea fișelor. |
| `employees:sensitive` | Citirea telefonului și salariului prin endpointul dedicat. |

| Cont | Rol | Scope-uri configurate | Lista publică | Fișă publică individuală | POST/PUT/DELETE | Date sensibile |
|---|---|---|---|---|---|---|
| `employee_demo` | `employee` | `employees:read` | Nu | Doar propria fișă, ID 1 în datele inițiale | Nu | Nu, nici pentru propria fișă |
| `hr_reader` | `hr_reader` | `employees:read` | Da | Orice fișă existentă | Nu | Nu |
| `hr_admin` | `hr_admin` | `employees:read`, `employees:write`, `employees:sensitive` | Da | Orice fișă existentă | Da | Orice fișă existentă |

Parolele sunt alese local, prin variabilele de mediu; nu sunt publicate în acest document.

## 6. Endpointuri API

| Metodă | Rută | Scop și răspuns de succes | Autorizare |
|---|---|---|---|
| GET | `/` | Mesaj de disponibilitate; 200 | Public |
| POST | `/token` | Verifică formularul și emite tokenul; 200 | Credențiale valide; nu cere un token anterior |
| GET | `/employees` | Lista de fișe publice; 200 | `employees:read` și rol `hr_reader` sau `hr_admin` |
| GET | `/employees/{employee_id}` | Fișă publică individuală; 200 | `employees:read`; HR pentru orice fișă sau rol `employee` pentru propriul ID |
| GET | `/employees/{employee_id}/sensitive` | Exact `id`, `phone`, `salary`; 200 | `employees:sensitive` și rol `hr_admin` |
| POST | `/employees` | Creează fișa, returnează date publice; 201 | `employees:write` și rol `hr_admin` |
| PUT | `/employees/{employee_id}` | Înlocuiește datele fișei, returnează date publice; 200 | `employees:write` și rol `hr_admin` |
| DELETE | `/employees/{employee_id}` | Șterge fișa; 204, fără corp | `employees:write` și rol `hr_admin` |

Parametrul `employee_id` trebuie să fie întreg. FastAPI expune și documentația generată la `/docs`, `/redoc` și schema la `/openapi.json`.

## 7. Instalare și configurare în Windows PowerShell

Instrucțiunile sunt destinate unei copii locale a proiectului. Deschide PowerShell în directorul care conține `app`, `tests` și `requirements.txt`. Nu este necesară activarea mediului virtual: comenzile folosesc explicit interpretul acestuia.

### 7.1. Python

Instalează CPython pentru Windows din [sursa oficială](https://www.python.org/downloads/windows/), cu acces la comanda `py`. Setul de dependențe necesită Python 3.11 sau mai nou; versiunea verificată în proiect este 3.13.9. Comenzile de mai jos aleg Python 3.13:

```powershell
py -3.13 --version
```

### 7.2. Mediu virtual și dependențe

Într-o copie nouă, creează mediul virtual și instalează dependențele:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Dacă există deja mediul virtual al proiectului, nu este necesar să îl recreezi. Fișierul de dependențe include atât bibliotecile aplicației, cât și cele necesare testelor. Versiunile directe au fost verificate în mediul existent; instalarea completă într-un mediu curat nu a fost încă verificată separat.

### 7.3. Configurație locală

Creează configurația pornind de la [.env.example](.env.example), fără să suprascrii un fișier local existent:

```powershell
if (-not (Test-Path -LiteralPath ".env")) {
    Copy-Item -LiteralPath ".env.example" -Destination ".env"
} else {
    Write-Host "Fișierul .env există deja; configurația locală a fost păstrată."
}
```

Generează pe calculatorul local o cheie aleatorie:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

Comanda produce 64 de caractere hexazecimale. Copiază rezultatul în `JWT_SECRET_KEY` din fișierul local și configurează manual parole distincte pentru cele trei conturi. Înlocuiește toate placeholder-ele din exemplu; ele sunt publice și nu constituie credențiale pentru utilizare reală.

| Variabilă obligatorie | Semnificație |
|---|---|
| `JWT_SECRET_KEY` | Cheia pentru semnarea JWT; aplicația cere minimum 32 de caractere. |
| `DEMO_EMPLOYEE_PASSWORD` | Parola contului `employee_demo`. |
| `DEMO_READER_PASSWORD` | Parola contului `hr_reader`. |
| `DEMO_ADMIN_PASSWORD` | Parola contului `hr_admin`. |

Configurația este încărcată la importarea aplicației. O cheie absentă sau prea scurtă, ori lipsa unei variabile obligatorii de parolă, împiedică pornirea. Variabilele deja definite în mediul procesului au prioritate față de fișierul local. Repornește serverul după schimbarea configurației.

Fișierul local de mediu conține valorile în clar și trebuie păstrat privat; `.gitignore` îl exclude. Pentru distribuire se folosește numai exemplul fără secrete.

### 7.4. Pornirea serverului

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

API-ul este disponibil local la [http://127.0.0.1:8000](http://127.0.0.1:8000). Oprirea se face cu `Ctrl+C`. La repornire, datele angajaților revin la cele definite inițial în cod.

## 8. Utilizarea Swagger UI

1. Deschide [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
2. Apasă **Authorize** și introdu numele unuia dintre cele trei conturi și parola configurată local. Câmpurile `client_id` și `client_secret` pot rămâne goale.
3. Selectează scope-urile corespunzătoare contului: `employees:read` pentru angajat sau HR reader; toate cele trei pentru administrator. Confirmă autorizarea și închide dialogul.
4. Deschide un endpoint, apasă **Try it out**, completează ID-ul sau corpul cererii și apasă **Execute**. Swagger transmite tokenul Bearer pentru cererile protejate.
5. Examinează codul HTTP și corpul răspunsului. Pentru DELETE reușit este normal ca răspunsul 204 să nu aibă corp.
6. Pentru schimbarea contului, folosește **Authorize → Logout**, apoi autentifică noul utilizator. Reautentifică-te după expirarea tokenului.

În implementarea actuală, `/token` emite lista de scope-uri configurată pentru cont; nu o reduce în funcție de selecția din formular. Bifarea unui scope în Swagger nu acordă drepturi suplimentare contului. Rolurile și scope-urile sunt verificate de API, indiferent de interfața folosită.

Apelarea manuală a endpointului `/token` prin **Try it out** afișează răspunsul de autentificare, dar nu înlocuiește autorizarea interfeței prin butonul **Authorize**.

Pentru observarea diferenței dintre autentificare și autorizare, încearcă lista angajaților fără autorizare (401), apoi cu `employee_demo` (403). Contul de angajat poate citi fișa cu ID 1, dar nu fișa cu ID 2. `hr_reader` poate citi fișele publice, însă accesul sensibil și scrierea sunt refuzate. `hr_admin` poate efectua aceste operații; ID-urile create trebuie preluate din răspunsul POST. Mesajele de audit apar în terminalul serverului.

## 9. Testare automată

Din rădăcina proiectului, rulează:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -v -p no:cacheprovider
```

`-B` evită generarea fișierelor bytecode, iar `-p no:cacheprovider` dezactivează cache-ul pytest. Serverul Uvicorn nu trebuie pornit pentru teste: `TestClient` apelează aplicația în procesul de test.

Suita conține **165 de teste**, număr reconfirmat prin colectare la redactarea documentației. În verificările anterioare, toate au trecut fără avertismente, inclusiv la rulări repetate și cu ordinea fișierelor inversată.

| Fișier | Categorie | Cazuri colectate |
|---|---|---:|
| `tests/test_auth_access.py` | Autentificare JWT și autorizare GET | 36 |
| `tests/test_crud_sensitive.py` | CRUD, scope-uri, roluri și date sensibile | 60 |
| `tests/test_audit.py` | Evenimente JSON, metadate, confidențialitate și absența succeselor false | 33 |
| `tests/test_error_security.py` | Mesaje sigure pentru 401, 403, 404, 422 și 500 | 36 |

Pentru verificarea numărului de teste fără executarea lor:

```powershell
.\.venv\Scripts\python.exe -B -m pytest --collect-only -q -p no:cacheprovider
```

Fixture-urile dezactivează încărcarea fișierului local de mediu înainte de importarea aplicației și folosesc exclusiv chei, parole și fișe fictive. Registrele sunt restaurate după fiecare test. Captura de audit este eliminată la final, iar erorile interne sunt simulate temporar prin `monkeypatch`, cu verificarea revenirii la comportamentul normal.

## 10. Limitări

- Datele sunt păstrate în memorie, fără persistență. Repornirea pierde modificările; mai multe procese de server nu ar împărți aceeași stare. Comanda de rulare folosește un singur proces.
- Conturile sunt demonstrative și definite în cod. Nu există înregistrare de utilizatori, administrare de conturi sau creare automată de cont la POST-ul unui angajat.
- Autentificarea este un mecanism JWT local simplificat, integrat cu formularul și schema de securitate FastAPI. Nu constituie un server OAuth 2.0 complet; nu există înregistrare de clienți, consimțământ, Authorization Code cu PKCE sau refresh tokens.
- Referințele OAuth explică terminologia și folosirea tokenurilor Bearer; nu indică implementarea integrală a standardului. Pentru sisteme reale trebuie consultate și recomandările actualizate din [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700).
- Nu există revocare individuală de tokenuri sau endpoint de logout pe server. Logout-ul din Swagger elimină autorizarea din interfață.
- Auditul acoperă numai cele patru tipuri de operații reușite selectate. Nu acoperă complet încercările refuzate și nu are stocare persistentă. Un eveniment confirmă execuția în aplicație, nu livrarea răspunsului către client.
- Mesajele 500 rămân generice cât timp debug-ul este dezactivat. Viitorii validatori personalizați trebuie să păstreze mesaje sigure, deoarece handlerul 422 transmite `msg`.
- Comanda locală folosește HTTP pe interfața de loopback. Nu sunt implementate configurarea TLS, limitarea numărului de cereri sau protecții complete împotriva încercărilor repetate de autentificare.
- Proiectul nu reprezintă o soluție completă de producție. Testele existente verifică scenariile definite, nu toate amenințările posibile; instalarea într-un mediu curat rămâne o verificare separată.

## 11. Referințe

- Arnaud Lauret, *The Design of Web APIs*, Manning, 2019, capitolul 8: [pagina editurii](https://www.manning.com/books/the-design-of-web-apis).
- FastAPI: [JWT și hashing-ul parolelor](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/) și [scope-uri OAuth2](https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/).
- OWASP: [API Security Top 10, ediția 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/), ca reper pentru riscurile de autentificare și autorizare la nivel de resursă și proprietate.
- IETF: [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519), pentru structura JWT și claim-urile utilizate.
- IETF: [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750), pentru transmiterea tokenurilor Bearer.
- IETF: [RFC 6749 — OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749), pentru cadrul conceptual OAuth 2.0.
- IETF: [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700), pentru recomandările de securitate actualizate.
