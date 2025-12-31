# Tabla de Contenidos
* [ADV-2025-9901 |SSH-Snake: Gusano de Red Autorreplicante](#adv-2025-9901---ssh-snake-gusano-de-red-autorreplicante)
    * [Detalles Técnicos](#detalles-técnicos)
    * [Tecnologias Afectadas](#tecnologias-afectadas)
    * [Como evitar vulnerabilidad](#evitar-esta-vulnerabilidad--mitigar-riesgos)
    * [Referencias](#documentacion-oficial-y-referencias)
* [MAL-2025-1024 | PyStoreRAT (Ecosistema PyPI)](#mal-2025-1024---pystorerat-malware-en-el-ecosistema-pypi)
    * [¿Qué significa PyStoreRAT?](#que-significa-pystorerat)
    * [Detalles Técnicos](#detalles-técnicos)
    * [Mitigación](#mitigación)
* [CVE-2025-62221 | Zero-Day Windows (EoP)](#cve-2025-62221---zero-day)
    * [De qué trata](#de-que-trata)
    * [Sistemas Afectados](#sistemas-afectados)
* [CVE-2025-55182 | React2Shell (RCE)](#cve-2025-55182---react2shell-rce-crítico-en-react-server-components)
    * [Tecnologías Afectadas](#tecnologias-afectadas)
    * [Evitar esta vulnerabilidad](#evitar-esta-vulnerabilidad--mitigar-riesgos)
---

# [ADV-2025-9901] - SSH-Snake: Gusano de Red Autorreplicante

> [!IMPORTANT]
>
> Esta amenaza consiste en un gusano de red (worm) diseñado para automatizar el movimiento lateral. Utiliza llaves SSH descubiertas en un sistema para propagarse de forma autónoma a través de toda una infraestructura de servidores.

### Detalles Técnicos

* ID: ADV-2025-9901 (Identificado por investigadores de seguridad en 2024/2025).
* Severidad: Alta / Crítica (Dependiendo de la exposición de llaves).
* Tipo: Gusano de red para movimiento lateral.
* Posible ataque: Una vez que el atacante obtiene acceso inicial, el script escanea el sistema buscando llaves privadas y archivos de hosts conocidos. Al encontrarlos, intenta conectarse automáticamente a cada destino, replicándose a sí mismo en cada nuevo servidor comprometido sin intervención humana.

### Tecnologias afectadas

* Sistemas Operativos: Distribuciones de Linux (Ubuntu, Debian, CentOS, RHEL).
* Protocolos: SSH (Secure Shell) con autenticación basada en llaves privadas.
* Entornos: Servidores en la nube (AWS, Azure, GCP) y centros de datos on-premise que no utilicen frases de contraseña (passphrases) en sus llaves.

> [!CAUTION]
>
> A diferencia de otros ataques, SSH-Snake es particularmente difícil de detectar porque utiliza herramientas legítimas del sistema y credenciales válidas encontradas en el propio servidor para moverse de un equipo a otro.

### Evitar esta vulnerabilidad / Mitigar riesgos

Para proteger los entornos contra este tipo de propagación automática, se recomienda seguir las siguientes medidas:

| Medida | Acción Correctiva |
| --- | --- |
| Cifrado de llaves | Implementar el uso obligatorio de passphrases en todas las llaves privadas. |
| SSH Agent | Deshabilitar SSH Agent Forwarding en servidores de salto o producción. |
| Limpieza de hosts | Mantener el archivo known_hosts depurado y limitar los permisos de lectura de las carpetas .ssh. |

### Documentación Oficial y Referencias

* [Análisis de Sysdig](https://www.google.com/search?q=https://sysdig.com/blog/ssh-snake-intelligent-worm/)
* [Informe de Threat Intel - SentinelOne](https://www.google.com/search?q=https://www.sentinelone.com/labs/ssh-snake-worm-analysis/)
* [Mitre ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

---

# [MAL-2025-1024] - PyStoreRAT: Malware en el Ecosistema PyPI

> [!CAUTION]
> 
> PyStoreRAT no es un error de código accidental (CVE), sino un malware diseñado intencionalmente (RAT - Remote Access Trojan) que se distribuyó a través de paquetes maliciosos en PyPI mediante typosquatting. Es una amenaza crítica para repositorios de trabajo como GitHub y servidores CI/CD.

### Que significa PyStoreRAT
Es el nombre que le pusieron los investigadores a uno de estos malwares:
- Py → porque el malware esta parcial o totalmente codificado con Python.
- Store → hace referencia a que no son stores oficiales, sino que se disfrazan como herramientas utiles.
- RAT → es el tipo de malware en este caso Remote Access Trojan.


### Detalles Técnicos
- ID: MAL-2025-1024 (Registro en bases de datos de malware de cadena de suministro).
- Tipo: Troyano de Acceso Remoto (RAT) / Infostealer.
- Posible ataque: Typosquatting (nombres de paquetes similares a populares como requests-py, boto3-session, etc) e inyección de dependencias.
- Mecanismo: Al clonar un repositorio disfrazado con este malware, instalar un paquete, un script setup.py oculto descarga un binario ofuscado que establece una conexión persistente vía C2 (Command & Control) utilizando el protocolo de Microsoft Store como túnel para evadir firewalls.

### Que hace el malware
- Roba credenciales, como archivos secretos .env, tokens, llaves SSH, sesiones de navegadores.
- Persistencia: Se inyecta en el proceso de inicio del sistema operativo (Windows/Linux).
- Captura de pantalla constante enviada al atacante.

### Tecnologías / Entornos Afectados
- Desarrolladores Python: Cualquier entorno que haya instalado paquetes maliciosos identificados.
- Pip: Versiones de pip que no verifiquen hashes de paquetes.
- Entornos CI/CD: Pipelines de GitHub Actions o GitLab que descarguen dependencias sin bloquear versiones específicas.

>[!IMPORTANT]
>
> A diferencia de una vulnerabilidad normal, eliminar el paquete malicioso no es suficiente para limpiar el sistema, ya que el malware instala una "puerta trasera" independiente del entorno de Python.

### Mitigación
Si sospechas que fuiste infectado y si usas principalmente python, o descargaste un paquete sospechoso, segui estos pasos:
1. Verifica ejecuta el siguiente comando `pip list`y analiza si hay algun paquete con nombre raro o sospechoso que contenga algun script malicioso.
2. Cambia las claves secretas y privadas que tenias en tu entorno.

> [!TIP]
> 
> Para prevenir futuros ataques de este tipo, utiliza siempre archivos requirements.txt con hashes verificados: `pip install --require-hashes -r requirements.txt`.

### Documentación Oficial y Referencias
- [PyPI Security](https://pypi.org/security/)
- [morphisec](https://www.morphisec.com/blog/pystorerat-a-new-ai-driven-supply-chain-malware-campaign-targeting-it-osint-professionals/)
- [Boradcom](https://www.broadcom.com/support/security-center/protection-bulletin/pystorerat-malware)

----

# [CVE-2025-62221] - Zero Day

> [!IMPORTANT]
>
> Esta vulnerabilidad afecta a un componente del sistema operativo que la mayoría de los usuarios utiliza sin saberlo: el Windows Cloud Files Mini Filter Driver (cldflt.sys).

## De que trata
Es una falla de Elevación de Privilegios (EoP). Lo que la hace peligrosa es que es un Zero-day, lo que significa que los atacantes la descubrieron y la empezaron a usar antes de que Microsoft tuviera el parche listo.

Un atacante que ya tiene acceso básico al equipo (un usuario normal sin permisos) puede ejecutar un script que aproveche ese error de memoria para engañar al sistema y obtener privilegios de SYSTEM (el nivel de control más alto en Windows).

> [!CAUTION]
> 
> **Estado:** Explotada activamente (Bajo ataque).
> **Gravedad:** 7.8 (Alta/Crítica en contexto de cadena de ataque).

**Sistemas Afectados:**
- Windows 10 (desde 1809 hasta 22H2).
- Windows 11 (21H2, 22H2, 23H2, 24H2).
- Windows Server 2019, 2022 y 2025.


> [!IMPORTANT]
>
> Se requiere la actualización acumulativa de **Diciembre 2025** para mitigar este riesgo.

### Documentacion oficial y referencias
- [Microsoft Security Response Center (MSRC)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-62221)
- [NIST](https://nvd.nist.gov/vuln/detail/CVE-2025-62221)
- [CISA](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24968)

----

# [CVE-2025-55182] - React2Shell: RCE Crítico en React Server Components

> [!IMPORTANT]
> 
> Esta vulnerabilidad es un **"Must-Patch"** inmediato. Es una vulnerabilidad del tipo RCE (Remote Code Execution) y afecta al núcleo de React 19 y, por extensión, a NextJs y cualquier otro framework que utilice React Server Components (RSC).

### Detalles Técnicos
- ID: CVE-2025-55182 (también rastreada inicialmente como CVE-2025-66478 en NextJS).
- Severidad: 10.0/10 (CRÍTICA).
- Tipo: Deserialización insegura de datos.
- Posible ataque: Un atacante puede enviar una solicitud HTTP maliciosa al protocolo "Flight" (el que usa RSC para pasar datos entre servidor y cliente). Al deserializar esta petición, el servidor ejecuta código arbitrario con los privilegios del proceso web. Incluso puede ejecutar codigo que vos mismo estes enviando.

### Tecnologias afectadas
- React: Versiones 19.0.0, 19.1.x, y 19.2.0.
- NextJS: Versiones 15.x y 16.x (que usan App Router), y versiones canary desde la 14.3.0.
- Otros: React Router RSC preview, Redwood SDK, Waku y plugins de Vite/Parcel para RSC.


> [!CAUTION]
>
> A partir de esta vulnerabilidad se confirmo que las aplicaciones creadas con create-next-app bajo configuraciones por defecto son vulnerables sin necesidad de que los desarrolladores haya cometido errores de código.

### Evitar esta vulnerabilidad / Mitigar riesgos

Si estas usando alguna de estas tecnologias actualiza a las versiones ya parcheadas que se detallan en la grilla.

| Tecnologia | Versión Segura (Parcheada) |
| :--- | :--- | 
| React |19.0.1, 19.1.2 o 19.2.1|
| Next.js 15/16 | 15.0.5, 15.1.9, 15.5.7, 16.0.7|
| Next.js 14 (Canary) | Downgrade a 14.2.35 o estable |

> [!TIP]
>
> Si usas Next.js, puedes ejecutar este comando para verificar y arreglar tu proyecto automáticamente: `npx fix-react2shell-next`

### Documentación Oficial y Referencias

- [Blog oficial React](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Vercel](https://vercel.com/changelog/cve-2025-55182)
- [Análisis de Wiz Research](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [NIST](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
