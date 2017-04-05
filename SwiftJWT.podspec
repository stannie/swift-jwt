Pod::Spec.new do |s|
  s.name        = "SwiftJWT"
  s.version     = "0.6"
  s.summary     = "a JSON Web Token implementation in Swift on iOS & OSX"
  s.homepage    = "git://github.com/stannie/swift-jwt"
  s.license     = { :type => "MIT", :file => 'LICENSE' }
  s.authors     = { "Stan P. van de Burgt" => "stan@vandeburgt.com" }
  s.social_media_url = 'https://twitter.com/stannie'

  s.ios.deployment_target = "9.0"
  s.osx.deployment_target = "10.9"
  # s.source   = { :git => "git://github.com/stannie/swift-jwt.git", :tag => s.version}
  s.source   = { :git => "git://github.com/stannie/swift-jwt.git", :branch => "master"}
  s.requires_arc = true

  # also needs CommonCrypto
  # see http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework
  # (answer by stephencelis) on how to import
  # s.frameworks = "CommonCrypto"

  s.subspec 'Core' do |core|
    core.source_files = "JWT/JWT/**/*.{swift,h}"

    # exclude ed25519 code
    core.exclude_files = "**/JWTNaCl.swift"
  end

  s.subspec 'with-ed25519' do |ed25519|
    ed25519.source_files = "JWT/JWT/**/*.{swift,h}"

    # needed only for the JWTNaCl sub class
    s.dependency "Sodium", "~> 0.3"
  end
end
