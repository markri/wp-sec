Feature: Test that JSON output is generated
  @output @json
  Scenario: wp-sec returns JSON output
    Given a WP install

    When I run `wp wp-sec check --output=json`
    Then STDOUT should contain:
      """
      {"core":0,"plugins":0,"themes":0}
      """
