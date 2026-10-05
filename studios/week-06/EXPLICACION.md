# Explicación didáctica de `solution.ipynb` (Week 6 Studio)

Guía para alguien que **no sabe nada de ciberseguridad**. Sigue el orden del notebook: Setup → §1 → §2 → §3 → §4. Para ver el código exacto de cada prueba, abre la celda correspondiente de [solution.ipynb](solution.ipynb).

---

## 0. Ideas base

### ¿Qué es una "inyección"?
Imagina un cocinero que obedece todo lo que oye. Si dictas "pon sal", pone sal. Pero si alguien más mete frases en tu dictado, el cocinero las obedece también, porque no distingue entre **tus instrucciones** y **datos ajenos**.

Una **inyección** es eso: un programa mezcla **datos escritos por el usuario** (un nombre, una contraseña) con **instrucciones** (código), y los datos terminan interpretados como instrucciones. Es una sola falla con tres "disfraces":

| Disfraz | Dónde se cuela | Nombre corto |
|---|---|---|
| Base de datos | SQL (lenguaje de consultas) | **SQLi** |
| Página web | HTML / JavaScript | **XSS** |
| Sistema operativo | Comandos de terminal | **cmdi** |

Las defensas también se parecen entre sí:

| Problema | Defensa |
|---|---|
| SQLi | **Consultas parametrizadas**: los valores viajan aparte de la consulta y nunca se interpretan como SQL |
| XSS | **Codificar la salida**: el texto del usuario se muestra como texto, no como código |
| cmdi | **No armar comandos pegando textos**; usar APIs que reciben argumentos separados |

### ¿Qué es un "oráculo"?
Una **prueba objetiva** que confirma que el problema es real. La lección central de la semana:

> Que algo *parezca* un problema no lo vuelve un hallazgo. Un hallazgo es real cuando un oráculo **sólido** confirma un efecto de seguridad.

Analogía: gritas en una cueva y vuelve el eco. Eso es **reflejo**, no prueba de que la cueva tenga un derrumbe. Para el derrumbe necesitas evidencia directa. En el notebook, "el eco" es ver tu texto en la respuesta, y la "evidencia directa" es otra cosa según el caso (un dato secreto que no debías ver, código que quedó sin neutralizar, etc.).

### ¿Qué es un "falso positivo"?
Una alarma que suena sin peligro real. Si tus herramientas lo hacen seguido, nadie confía en tu reporte. Por eso cada prueba incluye un **control benigno**: una entrada normal y legítima que **no** debe disparar la alarma. Si dispara, el oráculo está mal.

### El laboratorio
`vuln-web` es una app **vulnerable a propósito**, local (`127.0.0.1`), sin salida a internet.

| Endpoint | Qué hace | Estado |
|---|---|---|
| `POST /login` | Inicio de sesión | Vulnerable (SQLi) |
| `GET /?name=` | Saluda con tu nombre | Vulnerable (XSS) |
| `POST /ping` | "Hace ping" a un host (simulado) | Vulnerable (cmdi) |
| `GET /safe?name=` | El saludo, ya corregido | Seguro (sirve de contraste) |

> **Alcance:** todo corre en tu propia máquina. Probar estas técnicas en sistemas ajenos sin autorización es ilegal. Ver [ethics-and-scope.md](../../resources/ethics-and-scope.md).

---

## 1. Setup

**Qué hace:**
1. Localiza la carpeta raíz del curso (la que contiene `seclab/`) y la agrega al `sys.path` para poder importar.
2. Hace lo mismo con `studios/week-06` para importar `webharness` y `starter`.
3. Llama a `webharness.serve()`, que levanta la app **dentro del notebook** (puerto 8062), sin Docker.
4. Consulta `/health` y espera `{"status": "ok"}`.

**Analogía:** armar el laboratorio antes de experimentar.

> Tu app en el puerto 8000 se usa en una celda opcional (§1.4). El resto usa el 8062 porque es el que emplean los tests oficiales y da resultados reproducibles.

---

## 2. §1 — Task 1: tres hallazgos confirmados

Patrón común de las tres pruebas:

1. Se preparan las entradas de prueba (**payloads**) y un **control benigno**.
2. `run_payloads` (utilidad de `seclab.attack`) las envía una por una y consulta al oráculo.
3. `print_summary` muestra cuántas confirmó el oráculo por familia.

El trabajo real está en `starter.py`, en las funciones `confirm_sqli`, `confirm_xss` y `confirm_cmdi`.

### 2.1 SQLi en `/login`

- **La falla:** el servidor construye la consulta SQL **pegando** el usuario y la contraseña dentro del texto. Por eso lo escrito en esos campos puede alterar la consulta.
- **Qué mide el oráculo:** que la respuesta contenga el **secreto "canario"** (`FLAG-sqli-…`), un dato que un visitante sin credenciales nunca debería ver. Que el login "se comporte raro" solo sugiere el problema. Sacar el secreto lo demuestra.
- **Control benigno:** un usuario real con contraseña equivocada. Debe dar **0 de 1** (sin secreto). Si confirmara, el oráculo estaría detectando otra cosa.
- **Resultado:** las 3 pruebas de la familia `sqli` confirmaron; el control benigno no.
- **La defensa:** consulta parametrizada. Los valores se pasan como datos, jamás se interpretan como SQL.

### 2.2 XSS en `/?name=`

- **La falla:** el servidor pone tu texto dentro del HTML **sin codificarlo**. Si ese texto contiene una etiqueta `<script>`, el navegador de la víctima la tomaría como código y la ejecutaría.
- **El punto sutil:** que tu texto aparezca en la página (reflejo) **no** es XSS. Lo que importa es si la etiqueta llega **intacta** o **neutralizada**. Sin navegador disponible, el oráculo comprueba esa condición necesaria: la etiqueta `<script>` sobrevive sin escapar en la respuesta.
- **Por qué un oráculo propio:** el payload ya contiene la marca que buscamos, así que `contains_oracle` confirmaría el simple reflejo. Es justamente el falso positivo que esta tarea quiere evitar.
- **Contraste:** el **mismo** payload va a `/` (vulnerable) y a `/safe` (corregido, usa `html.escape`). El primero confirma; el segundo **no**. En `/safe` los símbolos `<` y `>` se transforman en `&lt;` y `&gt;`, que el navegador muestra como texto inofensivo. Ese "verdadero negativo" se reutiliza en el duelo.
- **La defensa:** codificar la salida (`html.escape` o el escapado automático de un motor de plantillas).

### 2.3 Inyección de comandos en `/ping`

- **La falla:** el servidor arma `ping -c 1 <host>` pegando el texto del usuario. Si en ese texto hay caracteres especiales del shell (por ejemplo `;`, `&&`, `|`), el sistema podría tratar lo que sigue como **otro comando**.
- **Seguridad del laboratorio:** la app **simula** la ejecución (no corre nada). Solo informa `injection_detected: true/false`, de modo que el problema se puede confirmar sin riesgo.
- **El oráculo:** lee el JSON y confirma solo si `injection_detected` es `True`. No se fía de que el texto aparezca repetido en la respuesta.
- **Control benigno:** un host normal sin caracteres especiales, que debe quedar limpio.
- **La defensa:** no construir comandos con cadenas; pasar los argumentos como lista a una API que no use shell, y validar el host contra un formato esperado.

### 2.4 Nota sobre confiabilidad
En estas pruebas todo es **determinista**: el mismo envío da siempre el mismo resultado (`reliability = 1.0`). Eso cambiará cuando el objetivo sea un **modelo de IA** (semanas 9–13): una prueba que funciona 2 de 5 veces es un hallazgo distinto de una que funciona 5 de 5. Por eso `run_payloads` admite `trials`.

### 2.5 Celda opcional en el puerto 8000
Repite una comprobación contra tu instancia ya levantada en `:8000` y verifica que se comporta igual que la del notebook (un login legítimo con contraseña errónea es rechazado, y el servicio responde en `/health`). Si el puerto no responde, se omite sin error.

---

## 3. §2 — Task 2: el duelo, LLM contra escáner

**Pregunta:** ¿quién encuentra mejor las vulnerabilidades leyendo el **código fuente**: un escáner clásico o un modelo de lenguaje?

### Los tres participantes

| Pieza | Qué es | ¿Quién la hace? |
|---|---|---|
| **Escáner clásico** (`regex_scanner`) | Reglas que buscan patrones **en una sola línea**; imita a Semgrep/CodeQL | Ya viene dado |
| **Brazo LLM** (`parse_llm_review`) | Convierte la reseña en prosa del modelo en resultados estructurados (`ScanResult`) | **Tú** (lo implementé en `starter.py`) |
| **Ground truth** (`ground_truth.json`) | La lista **correcta** de vulnerabilidades reales, hecha leyendo el código a mano | Creada por mí, pues faltaba en el repositorio |

### Qué hace `parse_llm_review`
Recibe texto como "1. [HIGH] SQL Injection in do_login: …" y, por cada línea, extrae:
- la **regla** (traduciendo el nombre en prosa con `RULE_ALIASES`; por ejemplo "SQL Injection" pasa a `sqli`),
- la **ubicación** (la función `do_...` que menciona),
- la severidad.

Debe ser **fiel**: no descarta los hallazgos dudosos del modelo. Si son reales o no lo decide el ground truth, no el parser.

### Cómo se puntúa
- **Precisión** = de lo que reportó, cuánto era real. Mide cuántas "falsas alarmas" produce.
- **Recall** (exhaustividad) = de lo real, cuánto encontró. Mide qué se le escapa.
- **F1** = un promedio de ambas.

### Resultados del notebook

| Herramienta | Aciertos | Falsos positivos | Pasó por alto | Precisión | Recall |
|---|---|---|---|---|---|
| Escáner (regex) | 2 | 0 | 1 | 100% | 67% |
| LLM | 3 | 2 | 0 | 60% | 100% |

### Las tres preguntas que importan más que el F1
1. **¿Qué alucinó el LLM?** Reportó un "control de acceso roto" en una app que **no tiene ningún código de autenticación**, y marcó como vulnerable el endpoint **ya corregido** (`/safe`). Son sus 2 falsos positivos.
2. **¿Qué se le escapó al escáner?** La inyección SQL. Su regla mira **una sola línea**, y la consulta está escrita en **dos líneas**, así que el patrón nunca coincide. Es una limitación real de las reglas simples.
3. **¿Alguno encontró el "Broken Access Control"?** No. El escáner no tiene regla para eso y el LLM lo inventó. El control de acceso trata de la **intención** ("¿debería este usuario poder hacer esto?"), no de la **sintaxis**, y por eso es el #1 de OWASP 2021: es lo que peor detecta la automatización.

**Moraleja:** el LLM tiene alto recall y alta alucinación; el escáner es preciso pero estrecho. Ninguno reemplaza al criterio humano.

---

## 4. §3 — Los tests oficiales

El notebook ejecuta `test_studio.py` **sin modificarlo**. Los 6 tests pasan:

| Test | Qué comprueba |
|---|---|
| SQLi confirmada por canario | Cada prueba `sqli` extrae el secreto |
| Login benigno no confirma | El oráculo no da falsos positivos |
| XSS: `/` sí, `/safe` no | Reflejo no es ejecución |
| cmdi confirmada, host benigno limpio | Oráculo correcto y control limpio |
| LLM parseado a `ScanResult` | Fiel, sin descartar lo dudoso |
| **Test de garantía** | El escáner **falla** en SQLi y **nadie** encuentra Broken Access Control |

El último es el "punto de la semana": ves fallar la automatización justo donde vive el #1 de OWASP.

---

## 5. §4 — Task 3: Control Scorecard y nota de divulgación

### ¿Qué es el Control Scorecard?
Una tabla del curso para evaluar **una defensa** con rigor y reemplazar frases como "pusimos un WAF, estamos protegidos". Obliga a responder: **¿qué garantiza este control, contra qué adversario y cómo lo sabes?**

En esta tarea se rellenan los ejes 1 a 4 para una **defensa concreta**: reemplazar la consulta armada con texto por una **consulta parametrizada** en el login.

| Eje | Pregunta | Resumen de lo que se respondió |
|---|---|---|
| **1. Modelo de amenaza** | ¿Quién ataca y qué puede hacer? | Atacante remoto sin credenciales que puede enviar cualquier texto a `/login` |
| **2. Garantía** | ¿Qué promete **y bajo qué condición**? | Los valores se tratan como datos, **siempre que** *todas* las consultas estén parametrizadas y no se pegue texto en SQL dinámico. Una sola consulta sin parametrizar reabre el hueco |
| **3. Cobertura** | ¿Qué fracción del ataque detiene? | Sobre nuestro conjunto de pruebas, todas se neutralizan y el login legítimo sigue funcionando. Es una **muestra**, no todo el espacio (una evaluación formal usa 20 o más) |
| **4. Bypass** | ¿Cómo se la rodea? | Se razonaron los casos: *SQLi de segundo orden* (un valor guardado de forma segura que luego se pega en otra consulta) y *posiciones no parametrizables* (nombres de tabla o columna, `ORDER BY`). Las pruebas clásicas fallan contra un punto totalmente parametrizado |

**Por qué el eje 2 es un condicional:** "es seguro" vale poco. "Es seguro **si** se cumple X" es una afirmación que se puede verificar o refutar.

**Por qué el eje 4 es obligatorio:** una defensa que nunca intentaste romper es una defensa que no evaluaste. Sin intento de bypass, el eje vale cero.

### Nota de divulgación responsable (dos líneas)
Es el mensaje que enviarías al dueño de una aplicación **real que estés autorizado a probar**. Dice **qué** pasa y **dónde**, el **impacto** y cómo **arreglarlo**. Aquí es una plantilla (el objetivo es `127.0.0.1`), no un reporte enviado.

---

## 6. Resumen

- La inyección es **una sola falla** (datos que cruzan a un canal de control) con tres disfraces y defensas parecidas.
- Un hallazgo **no es real** hasta que un oráculo sólido lo confirma, y cada oráculo necesita su **control benigno**.
- **Reflejo no es ejecución**; por eso `/` confirma y `/safe` no.
- El **LLM** encuentra mucho pero inventa; el **escáner** es preciso pero se pierde lo que no cabe en su regla. **Ninguno** halló el control de acceso roto.
- Evaluar una defensa es medir **garantía, cobertura y bypass**, y reconocer sus límites.

## Glosario rápido

| Término | Significado |
|---|---|
| **Payload** | Entrada de prueba que se envía al objetivo |
| **Oráculo** | Prueba objetiva de que el efecto ocurrió |
| **Control benigno** | Entrada legítima que no debe disparar la alarma |
| **Falso positivo** | Alarma sin problema real |
| **Ground truth** | Lista correcta de problemas reales, hecha a mano |
| **Precisión / Recall** | Cuántas alarmas son reales / cuántos problemas reales se encontraron |
| **Canario** | Dato secreto plantado para detectar una fuga |
| **OWASP** | Organización que publica el listado de riesgos web más comunes |
