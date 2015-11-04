Pod::Spec.new do |s|
  s.name        = "SwiftJWT"
  s.version     = "0.5"
  s.summary     = "a JSON Web Token implementation in Swift on iOS & OSX"
  s.homepage    = "git://github.com/stannie/swift-jwt"
  s.license     = { :type => "MIT", :file => 'LICENSE' }
  s.authors     = { "Stan P. van de Burgt" => "stan@vandeburgt.com" }
  s.social_media_url = 'https://twitter.com/stannie'

  s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.9"
  # s.source   = { :git => "git://github.com/stannie/swift-jwt.git", :tag => s.version}
  s.source   = { :git => "git://github.com/stannie/swift-jwt.git", :branch => "master"}

  # https://github.com/stannie/swift-jwt.git git@github.com:stannie/swift-jwt.git
  s.source_files = "JWT/JWT/*.{swift,h}"
  s.requires_arc = true

  # s.frameworks = "CommonCrypto"

  # needs https://github.com/jedisct1/swift-sodium checkout 176033d7c1cbc4dfe4bed648aa230c9e14ab9426
  # but only for the JWTNaCl sub class
  # s.dependency = "swift-sodium"

  # also needs CommonCrypto
  # see http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework
  # (answer by stephencelis) on how to import
end
