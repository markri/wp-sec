Feature: Test that Nagios output is generated
  @output @nagios
  Scenario: wp-sec returns Nagios output
    Given a WP install

    When I run `wp wp-sec check --output=nagios`
    Then STDOUT should contain:
      """
      OK - no vulnerabilities found
      """
