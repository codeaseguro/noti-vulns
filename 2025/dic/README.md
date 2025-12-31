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
