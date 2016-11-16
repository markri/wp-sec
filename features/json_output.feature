Feature: Test that JSON output is generated
  @output @json
  Scenario: wp-sec returns JSON output
    Given a WP install

    When I run `wp wp-sec check --output=json`
    Then STDOUT should contain:
      """
      {"core":{"count":0,"details":[]},"plugins":{"count":0,"details":[]},"themes":{"count":0,"details":[]}}
      """
