#
# Be sure to run `pod lib lint CSPHeader.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'CSPHeader'
  s.version          = '0.4.0'
  s.summary          = 'CSPHeader parses, manipulates and generates Content-Security-Policy headers.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
This library parses, manipulates and generates Content-Security-Policy (CSP) headers.

This is especially useful, when you want to modify a CSP of a web page you display
in your app and which needs some JavaScript injected.

You could also build a CSP analyzer or generator app with it.

This is the first release and may contain some rough edges.

Pull requests wellcome!
                       DESC

  s.homepage         = 'https://github.com/tladesignz/CSPHeader'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Benjamin Erhart' => 'berhart@netzarchitekten.com' }
  s.source           = { :git => 'https://github.com/tladesignz/CSPHeader.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/tladesignz'

  s.ios.deployment_target = '8.0'

  s.swift_versions = '5.0'

  s.source_files = 'CSPHeader/Classes/**/*'
  
  # s.resource_bundles = {
  #   'CSPHeader' => ['CSPHeader/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
