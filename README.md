# Pruebas de concepto contra el heap de Windows

En este repositorio se recoge una serie de pruebas de concepto que implementan los siguientes ataques contra el heap de Windows:
- **use-after-free:** ataque que busca aprovechar fallos de implementación en las aplicaciones que provocan el uso de un espacio de memoria dinámica ya liberada.

- **double-free:** ataque basado en el aprovechamiento de la liberación de un espacio de memoria dinámica ya liberado, lo cual corrompe las listas de almacenamiento de porciones de memoria (*heap entries* o *chunks*) vacías.

- **heap overflow:** ataque que trata de acceder a un espacio de la memoria *heap* fuera de los límites del espacio reservado por el atacant.

- **heap spraying:** ataque complementario que busca esparcir por la memoria dinámica un *payload* destinado a acciones maliciosas. Este *payload* está pensado para ser accedido mediante la modificación del flujo de control de la aplicación, modificación realizada por ataques como los anteriores.

En concreto, estos ataques estan pensados para su compilación en GCC (el comando concreto se muestra dentro de cada fichero) y ejecución en Windows 10, ya que son ataques pensados para soportar las mejoras en el heap introducidas en las versiones de NT heap de Windows a partir de Windows 10.

En el repositorio no sólo se incluyen los POCs y sus distintas versiones, sino que se visualzian otros ficheros como los POCs relativos para 32 bits u otras pruebas que ayudaron al desarrollo del POC final. Los detalles del objetivo y desarrollo (en los propios POCs también se incluyen comentarios que ayudan a la comprensión de estos) de estos POCs se puede visualziar en [https://webdiis.unizar.es/~ricardo/files/TFMs/Deteccion-patrones-identificacion-ataques-heap-Windows_TFM_ULE.pdf](https://webdiis.unizar.es/~ricardo/files/TFMs/Deteccion-patrones-identificacion-ataques-heap-Windows_TFM_ULE.pdf)

# Proofs of Concept Against the Windows Heap

This repository contains a series of proof-of-concept implementations of the following attacks against the Windows heap:

- **use-after-free:** an attack that exploits implementation flaws in applications that result in the use of dynamically allocated memory that has already been freed.

- **double-free:** an attack based on freeing a previously freed memory region again, which corrupts the storage lists of free memory blocks (*heap entries* or *chunks*).

- **heap overflow:** an attack that attempts to access heap memory outside the bounds of the space allocated by the attacker.

- **heap spraying:** a complementary attack that aims to spread a malicious *payload* across dynamic memory. This payload is intended to be executed through control flow manipulation of the application, typically achieved using attacks like the ones described above.

Specifically, these attacks are designed to be compiled using GCC (the exact command is provided within each file) and executed on Windows 10, as they are built to support the heap improvements introduced in Windows NT heap versions starting from Windows 10.

The repository includes not only the POCs and their different versions, but also additional files such as 32-bit related POCs and other tests that contributed to the development of the final POCs. Further details about the objectives and development (the POCs themselves also include comments to aid understanding) can be found at:
[https://webdiis.unizar.es/~ricardo/files/TFMs/Deteccion-patrones-identificacion-ataques-heap-Windows_TFM_ULE.pdf](https://webdiis.unizar.es/~ricardo/files/TFMs/Deteccion-patrones-identificacion-ataques-heap-Windows_TFM_ULE.pdf)
