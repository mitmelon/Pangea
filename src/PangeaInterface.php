<?php
namespace Pangea;

interface PangeaInterface {
    //Interface method to receive parent properties
    public function setParentProperties(Pangea $parent, $endpoint);
}