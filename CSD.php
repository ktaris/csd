<?php

/**
 * @copyright Copyright (c) 2017 Carlos Ramos
 * @package ktaris-csd
 * @version 0.1.0
 */

namespace ktaris\csd;

use ktaris\csd\Cer;
use ktaris\csd\Key;

class CSD
{
    use Cer, Key;

    public function leer()
    {
        $this->leerCer();
        $this->generarArchivoKeyPem();
    }

    // ==================================================================
    //
    // Funciones públicas para exponer datos.
    //
    // ------------------------------------------------------------------

    public function getCerPem()
    {
        return $this->_contenido_cer_pem;
    }

    public function getKeyPem()
    {
        return $this->_contenido_key_pem;
    }
}
