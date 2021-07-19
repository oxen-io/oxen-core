#pragma once

namespace wallet
{

  class Keys
  {
  public:

    virtual cryptonote::account_public_address GetAddress() = 0;

  };

} // namespace wallet
