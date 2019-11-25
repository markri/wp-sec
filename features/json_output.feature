Feature: Test that JSON output is generated
  @output @json
  Scenario: wp-sec returns JSON output
    Given a WP install

    When I run `wp wp-sec check --output=json --token=$TOKEN`

    Then STDOUT should be a JSON object with the property:
      """
      core
      """
    And STDOUT should be a JSON object with the property:
      """
      plugins
      """
    And STDOUT should be a JSON object with the property:
      """
      themes
      """
