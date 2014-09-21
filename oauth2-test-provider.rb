#!/usr/bin/env ruby
#! coding: utf-8

require 'sinatra'
require 'json'
require 'slim'
require 'active_support'
require 'base64'

configure do
  set :port, 4000
end

helpers do
  def secret
    @secret ||= SecureRandom.random_bytes(64)
  end

  def key_generator
    @key_generator ||= ActiveSupport::KeyGenerator.new(secret)
  end

  def key(hash)
    key_generator.generate_key(hash)
  end

  def encryptor
    @encryptor ||= ActiveSupport::MessageEncryptor.new(key('password'), key('salt'))
  end

  def authorized?
    @auth ||= Rack::Auth::Basic::Request.new(request.env)
    @auth.provided? and @auth.basic? and @auth.credentials and @auth.credentials[0] == @auth.credentials[1]
  end

  def code
    c = "#{Time.now.to_i}:#{@auth.credentials[0]}"
    #c = encryptor.encrypt_and_sign(c)
    c = Base64.urlsafe_encode64(c)
  end

  def get_user(c)
    begin
      c = Base64.urlsafe_decode64(c)
      #c = encryptor.decrypt_and_verify(c)
      time, user = c.split(':', 2)
      raise unless user
      raise unless Time.now.to_i <= time.to_i + 5
      user
    rescue => err
    puts err.inspect
    puts err.backtrace
      nil
    end
  end
end

get '/oauth/authorize' do
  uri = URI.parse(params[:redirect_uri])
  query = []
  query << uri.query if uri.query
  query << "state=#{params[:state]}" if params[:state]

  if authorized?
    query << "code=#{code}"
    uri.query = query.join('&')
    redirect uri
  else
    query << "error=unauthorized_client"
    uri.query = query.join('&')
    @redirect_uri = uri
    headers['WWW-Authenticate'] = 'Basic realm="Restricted Area"'
    cache_control :no_cache
    halt 401, slim(:denied)
  end
end

post '/oauth/token' do
  content_type 'application/json', encoding: 'utf-8'
  cache_control :no_cache
  begin
    user = get_user(params[:code])
    puts "user = #{user}"
    {
      access_token: user,
      token_type: "user",
    }.to_json
  rescue => err
    puts err.inspect, err.backtrace
    {
      error: "invalid_request",
    }.to_json
  end
end

__END__

@@denied
doctype html
html
  header
    meta http-equiv="refresh" content="0; url=#{@redirect_uri}"
  body
    | Not authorized.
