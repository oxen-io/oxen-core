#pragma once

#include "keys.hpp"
#include "transaction_scanner.hpp"

#include <memory>
#include <string_view>

namespace wallet
{

  class Wallet
  {
  public:

    Wallet(std::shared_ptr<Keys> _keyManager,
           std::shared_ptr<TransactionScanner> _txScanner,
           std::shared_ptr<TransactionConstructor> _txConstructor,
           std::string_view dbFilename,
           std::string_view dbPassword);

    /*** Signature TBD ***
     *
     * GetBalance
     * GetUnlockedBalance
     * GetAddress
     * GetSubaddress
     *
     */

  private:

    std::shared_ptr<Keys> keyManager;
    std::shared_ptr<TransactionScanner> txScanner;
    std::shared_ptr<TransactionConstructor> txConstructor;
  };

} // namespace wallet
