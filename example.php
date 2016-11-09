<?php

  $client = new PubstreamOpenX(
      $clientId,
      $clientSecret,
      $realm,
      $base_url
  );
  
  $login = $client->login($username, $password);
  
  if ($login){
      $sites = $client->get('site'); //return a streamed response
      $result = \json_decode($result->getBody()->getContents(), true);
      var_dump($result);
  }
