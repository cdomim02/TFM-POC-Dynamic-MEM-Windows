# Pruebas de concepto contra el heap de Windows

En este repositorio se recoge una serie de pruebas de concepto que implementan los siguientes ataques contra el heap de Windows:
- **use-after-free:** ataque que busca aprovechar fallos de implementación en las aplicaciones que provocan el uso de un espacio de memoria dinámica ya liberada.

- **double-free:** ataque basado en el aprovechamiento de la liberación de un espacio de memoria dinámica ya liberado, lo cual corrompe las listas de almacenamiento de porciones de memoria (*heap entries* o *chunks*) vacías.

- **heap overflow:** ataque que trata de acceder a un espacio de la memoria *heap* que no pertenece al proceso o usuario que realiza dicho ataque.

- **heap spraying:** ataque complementario que busca esparcir por la memoria dinámica un *payload* destinado a acciones maliciosas. Este *payload* está pensado para ser accedido mediante la modificación del flujo de control de la aplicación, modificación realizada por ataques como los anteriores.

En concreto, estos ataques estan pensados para su compilación en GCC (el comando concreto se muestra dentro de cada fichero) y ejecución en Windows 10, ya que son ataques pensados para soportar las mejoras en el heap introducidas en las versiones de NT heap de Windows a partir de Windows 10.

En el repositorio no sólo se incluyen los POCs y sus distintas versiones, sino que se visualzian otros ficheros como los POCs relativos para 32 bits u otras pruebas que ayudaron al desarrollo del POC final. Los detalles del objetivo y desarrollo (en los propios POCs también se incluyen comentarios que ayudan a la comprensión de estos) de estos POCs se puede visualziar en <TODO: enlace al TFM>.
