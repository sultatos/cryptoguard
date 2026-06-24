Feature: Envelope encryption round trip
  As an API client
  I want to encrypt files and download them decrypted
  So that file contents are protected at rest but recoverable intact

  Scenario: Round-trip a multi-chunk file
    Given a running CryptoGuard service
    When I encrypt a file named "report.bin" with 200000 bytes of content
    Then the response status is 201
    And the encrypted file can be downloaded
    And the downloaded content matches the original

  Scenario: Round-trip an empty file
    Given a running CryptoGuard service
    When I encrypt a file named "empty.bin" with 0 bytes of content
    Then the response status is 201
    And the encrypted file can be downloaded
    And the downloaded content matches the original

  Scenario: Decrypting an unknown file id returns 404
    Given a running CryptoGuard service
    When I request decryption of file id "00000000-0000-0000-0000-000000000000"
    Then the response status is 404

  Scenario: Decrypting a malformed file id returns 400
    Given a running CryptoGuard service
    When I request decryption of file id "not-a-uuid"
    Then the response status is 400

  Scenario: Encrypting with no file field is rejected
    Given a running CryptoGuard service
    When I submit a multipart form with no file field
    Then the response status is 400
