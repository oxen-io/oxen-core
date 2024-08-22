// (Included from simplewallet.cpp when compiling with MMS support)

// MMS
// ---------------------------------------------------------------------------------------------------

// Access to the message store, or more exactly to the list of the messages that can be changed
// by the idle thread, is guarded by the same mutex-based mechanism as access to the wallet
// as a whole and thus e.g. uses the "LOCK_IDLE_SCOPE" macro. This is a little over-cautious, but
// simple and safe. Care has to be taken however where MMS methods call other simplewallet methods
// that use "LOCK_IDLE_SCOPE" as this cannot be nested!

// Methods for commands like "export_multisig_info" usually read data from file(s) or write data
// to files. The MMS calls now those methods as well, to produce data for messages and to process
// data from messages. As it would be quite inconvenient for the MMS to write data for such methods
// to files first or get data out of result files after the call, those methods detect a call from
// the MMS and expect data as arguments instead of files and give back data by calling
// 'process_wallet_created_data'.

//----------------------------------------------------------------------------------------------------
void simple_wallet::check_for_messages() {
    try {
        std::vector<mms::message> new_messages;
        bool new_message =
                get_message_store().check_for_messages(get_multisig_wallet_state(), new_messages);
        if (new_message) {
            message_writer(epee::console_color_magenta, true) << tr("MMS received new message");
            list_mms_messages(new_messages);
            m_cmd_binder.print_prompt();
        }
    } catch (...) {
    }
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_mms() {
    // Check for new MMS messages;
    // For simplicity auto message check is ALSO controlled by "m_auto_refresh_enabled" and has no
    // separate thread either; thread syncing is tricky enough with only this one idle thread here
    if (m_auto_refresh_enabled && get_message_store().get_active()) {
        check_for_messages();
    }
    return true;
}

bool simple_wallet::user_confirms(const std::string& question) {
    std::string answer = input_line(question + tr(" (Y/Yes/N/No): "));
    return !std::cin.eof() && command_line::is_yes(answer);
}

bool simple_wallet::get_number_from_arg(
        const std::string& arg,
        uint32_t& number,
        const uint32_t lower_bound,
        const uint32_t upper_bound) {
    bool valid = false;
    try {
        number = boost::lexical_cast<uint32_t>(arg);
        valid = (number >= lower_bound) && (number <= upper_bound);
    } catch (const boost::bad_lexical_cast&) {
    }
    return valid;
}

bool simple_wallet::choose_mms_processing(
        const std::vector<mms::processing_data>& data_list, uint32_t& choice) {
    size_t choices = data_list.size();
    if (choices == 1) {
        choice = 0;
        return true;
    }
    mms::message_store& ms = m_wallet->get_message_store();
    message_writer() << tr("Choose processing:");
    std::string text;
    for (size_t i = 0; i < choices; ++i) {
        const mms::processing_data& data = data_list[i];
        text = std::to_string(i + 1) + ": ";
        switch (data.processing) {
            case mms::message_processing::sign_tx: text += tr("Sign tx"); break;
            case mms::message_processing::send_tx: {
                mms::message m;
                ms.get_message_by_id(data.message_ids[0], m);
                if (m.type == mms::message_type::fully_signed_tx) {
                    text += tr("Send the tx for submission to ");
                } else {
                    text += tr("Send the tx for signing to ");
                }
                mms::authorized_signer signer = ms.get_signer(data.receiving_signer_index);
                text += ms.signer_to_string(signer, 50);
                break;
            }
            case mms::message_processing::submit_tx: text += tr("Submit tx"); break;
            default: text += tr("unknown"); break;
        }
        message_writer() << text;
    }

    std::string line = input_line(tr("Choice: "));
    if (std::cin.eof() || line.empty()) {
        return false;
    }
    bool choice_ok = get_number_from_arg(line, choice, 1, choices);
    if (choice_ok) {
        choice--;
    } else {
        fail_msg_writer() << tr("Wrong choice");
    }
    return choice_ok;
}

void simple_wallet::list_mms_messages(const std::vector<mms::message>& messages) {
    message_writer() << boost::format("%4s %-4s %-30s %-21s %7s %3s %-15s %-40s") % tr("Id") %
                                tr("I/O") % tr("Authorized Signer") % tr("Message Type") %
                                tr("Height") % tr("R") % tr("Message State") % tr("Since");
    mms::message_store& ms = m_wallet->get_message_store();
    uint64_t now = (uint64_t)time(NULL);
    for (size_t i = 0; i < messages.size(); ++i) {
        const mms::message& m = messages[i];
        const mms::authorized_signer& signer = ms.get_signer(m.signer_index);
        bool highlight = (m.state == mms::message_state::ready_to_send) ||
                         (m.state == mms::message_state::waiting);
        message_writer(
                m.direction == mms::message_direction::out ? epee::console_color_green
                                                           : epee::console_color_magenta,
                highlight)
                << boost::format("%4s %-4s %-30s %-21s %7s %3s %-15s %-40s") % m.id %
                           ms.message_direction_to_string(m.direction) %
                           ms.signer_to_string(signer, 30) % ms.message_type_to_string(m.type) %
                           m.wallet_height % m.round % ms.message_state_to_string(m.state) %
                           (tools::get_human_readable_timestamp(m.modified) + ", " +
                            tools::get_human_readable_timespan(
                                    std::chrono::seconds(now - m.modified)) +
                            tr(" ago"));
    }
}

void simple_wallet::list_signers(const std::vector<mms::authorized_signer>& signers) {
    message_writer() << boost::format("%2s %-20s %-s") % tr("#") % tr("Label") %
                                tr("Transport Address");
    message_writer() << boost::format("%2s %-20s %-s") % "" % tr("Auto-Config Token") %
                                tr("Oxen Address");
    for (size_t i = 0; i < signers.size(); ++i) {
        const mms::authorized_signer& signer = signers[i];
        std::string label = signer.label.empty() ? tr("<not set>") : signer.label;
        std::string monero_address;
        if (signer.monero_address_known) {
            monero_address =
                    get_account_address_as_str(m_wallet->nettype(), false, signer.monero_address);
        } else {
            monero_address = tr("<not set>");
        }
        std::string transport_address =
                signer.transport_address.empty() ? tr("<not set>") : signer.transport_address;
        message_writer() << boost::format("%2s %-20s %-s") % (i + 1) % label % transport_address;
        message_writer() << boost::format("%2s %-20s %-s") % "" % signer.auto_config_token %
                                    monero_address;
        message_writer() << "";
    }
}

void simple_wallet::add_signer_config_messages() {
    mms::message_store& ms = m_wallet->get_message_store();
    std::string signer_config;
    ms.get_signer_config(signer_config);

    const std::vector<mms::authorized_signer> signers = ms.get_all_signers();
    mms::multisig_wallet_state state = get_multisig_wallet_state();
    uint32_t num_authorized_signers = ms.get_num_authorized_signers();
    for (uint32_t i = 1 /* without me */; i < num_authorized_signers; ++i) {
        ms.add_message(
                state,
                i,
                mms::message_type::signer_config,
                mms::message_direction::out,
                signer_config);
    }
}

void simple_wallet::show_message(const mms::message& m) {
    mms::message_store& ms = m_wallet->get_message_store();
    const mms::authorized_signer& signer = ms.get_signer(m.signer_index);
    bool display_content;
    std::string sanitized_text;
    switch (m.type) {
        case mms::message_type::key_set:
        case mms::message_type::additional_key_set:
        case mms::message_type::note:
            display_content = true;
            ms.get_sanitized_message_text(m, sanitized_text);
            break;
        default: display_content = false;
    }
    uint64_t now = (uint64_t)time(NULL);
    message_writer() << "";
    message_writer() << tr("Message ") << m.id;
    message_writer() << tr("In/out: ") << ms.message_direction_to_string(m.direction);
    message_writer() << tr("Type: ") << ms.message_type_to_string(m.type);
    message_writer() << tr("State: ")
                     << boost::format(tr("%s since %s, %s ago")) %
                                ms.message_state_to_string(m.state) %
                                tools::get_human_readable_timestamp(m.modified) %
                                tools::get_human_readable_timespan(
                                        std::chrono::seconds(now - m.modified));
    if (m.sent == 0) {
        message_writer() << tr("Sent: Never");
    } else {
        message_writer() << boost::format(tr("Sent: %s, %s ago")) %
                                    tools::get_human_readable_timestamp(m.sent) %
                                    tools::get_human_readable_timespan(
                                            std::chrono::seconds(now - m.sent));
    }
    message_writer() << tr("Authorized signer: ") << ms.signer_to_string(signer, 100);
    message_writer() << tr("Content size: ") << m.content.length() << tr(" bytes");
    message_writer() << tr("Content: ") << (display_content ? sanitized_text : tr("(binary data)"));

    if (m.type == mms::message_type::note) {
        // Showing a note and read its text is "processing" it: Set the state accordingly
        // which will also delete it from Bitmessage as a side effect
        // (Without this little "twist" it would never change the state, and never get deleted)
        ms.set_message_processed_or_sent(m.id);
    }
}

void simple_wallet::ask_send_all_ready_messages() {
    mms::message_store& ms = m_wallet->get_message_store();
    std::vector<mms::message> ready_messages;
    const std::vector<mms::message>& messages = ms.get_all_messages();
    for (size_t i = 0; i < messages.size(); ++i) {
        const mms::message& m = messages[i];
        if (m.state == mms::message_state::ready_to_send) {
            ready_messages.push_back(m);
        }
    }
    if (ready_messages.size() != 0) {
        list_mms_messages(ready_messages);
        bool send = ms.get_auto_send();
        if (!send) {
            send = user_confirms(tr("Send these messages now?"));
        }
        if (send) {
            mms::multisig_wallet_state state = get_multisig_wallet_state();
            for (size_t i = 0; i < ready_messages.size(); ++i) {
                ms.send_message(state, ready_messages[i].id);
                ms.set_message_processed_or_sent(ready_messages[i].id);
            }
            success_msg_writer() << tr("Queued for sending.");
        }
    }
}

bool simple_wallet::get_message_from_arg(const std::string& arg, mms::message& m) {
    mms::message_store& ms = m_wallet->get_message_store();
    bool valid_id = false;
    uint32_t id;
    try {
        id = (uint32_t)boost::lexical_cast<uint32_t>(arg);
        valid_id = ms.get_message_by_id(id, m);
    } catch (const boost::bad_lexical_cast&) {
    }
    if (!valid_id) {
        fail_msg_writer() << tr("Invalid message id");
    }
    return valid_id;
}

void simple_wallet::mms_init(const std::vector<std::string>& args) {
    if (args.size() != 3) {
        fail_msg_writer() << tr(
                "usage: mms init <required_signers>/<authorized_signers> <own_label> "
                "<own_transport_address>");
        return;
    }
    mms::message_store& ms = m_wallet->get_message_store();
    if (ms.get_active()) {
        if (!user_confirms(tr("The MMS is already initialized. Re-initialize by deleting all "
                              "signer info and messages?"))) {
            return;
        }
    }
    uint32_t num_required_signers;
    uint32_t num_authorized_signers;
    const std::string& mn = args[0];
    std::vector<std::string> numbers;
    boost::split(numbers, mn, boost::is_any_of("/"));
    bool mn_ok = (numbers.size() == 2) &&
                 get_number_from_arg(numbers[1], num_authorized_signers, 2, 100) &&
                 get_number_from_arg(numbers[0], num_required_signers, 2, num_authorized_signers);
    if (!mn_ok) {
        fail_msg_writer() << tr(
                "Error in the number of required signers and/or authorized signers");
        return;
    }
    LOCK_IDLE_SCOPE();
    ms.init(get_multisig_wallet_state(),
            args[1],
            args[2],
            num_authorized_signers,
            num_required_signers);
}

void simple_wallet::mms_info(const std::vector<std::string>& args) {
    mms::message_store& ms = m_wallet->get_message_store();
    if (ms.get_active()) {
        message_writer() << boost::format("The MMS is active for %s/%s multisig.") %
                                    ms.get_num_required_signers() % ms.get_num_authorized_signers();
    } else {
        message_writer() << tr("The MMS is not active.");
    }
}

void simple_wallet::mms_signer(const std::vector<std::string>& args) {
    mms::message_store& ms = m_wallet->get_message_store();
    const std::vector<mms::authorized_signer>& signers = ms.get_all_signers();
    if (args.size() == 0) {
        // Without further parameters list all defined signers
        list_signers(signers);
        return;
    }

    uint32_t index;
    bool index_valid = get_number_from_arg(args[0], index, 1, ms.get_num_authorized_signers());
    if (index_valid) {
        index--;
    } else {
        fail_msg_writer() << tr("Invalid signer number ") + args[0];
        return;
    }
    if ((args.size() < 2) || (args.size() > 4)) {
        fail_msg_writer() << tr(
                "mms signer [<number> <label> [<transport_address> [<oxen_address>]]]");
        return;
    }

    std::optional<std::string> label = args[1];
    std::optional<std::string> transport_address;
    if (args.size() >= 3) {
        transport_address = args[2];
    }
    std::optional<cryptonote::account_public_address> monero_address;
    LOCK_IDLE_SCOPE();
    mms::multisig_wallet_state state = get_multisig_wallet_state();
    if (args.size() == 4) {
        cryptonote::address_parse_info info;
        bool ok = cryptonote::get_account_address_from_str(info, m_wallet->nettype(), args[3]);
        if (!ok) {
            fail_msg_writer() << tr("Invalid Oxen address");
            return;
        }
        monero_address = info.address;
        const std::vector<mms::message>& messages = ms.get_all_messages();
        if ((messages.size() > 0) || state.multisig) {
            fail_msg_writer() << tr("Wallet state does not allow changing Oxen addresses anymore");
            return;
        }
    }
    ms.set_signer(state, index, label, transport_address, monero_address);
}

void simple_wallet::mms_list(const std::vector<std::string>& args) {
    mms::message_store& ms = m_wallet->get_message_store();
    if (args.size() != 0) {
        fail_msg_writer() << tr("Usage: mms list");
        return;
    }
    LOCK_IDLE_SCOPE();
    const std::vector<mms::message>& messages = ms.get_all_messages();
    list_mms_messages(messages);
}

void simple_wallet::mms_next(const std::vector<std::string>& args) {
    mms::message_store& ms = m_wallet->get_message_store();
    if ((args.size() > 1) || ((args.size() == 1) && (args[0] != "sync"))) {
        fail_msg_writer() << tr("Usage: mms next [sync]");
        return;
    }
    bool avail = false;
    std::vector<mms::processing_data> data_list;
    bool force_sync = false;
    uint32_t choice = 0;
    {
        LOCK_IDLE_SCOPE();
        if ((args.size() == 1) && (args[0] == "sync")) {
            // Force the MMS to process any waiting sync info although on its own it would just
            // ignore those messages because no need to process them can be seen
            force_sync = true;
        }
        std::string wait_reason;
        {
            avail = ms.get_processable_messages(
                    get_multisig_wallet_state(), force_sync, data_list, wait_reason);
        }
        if (avail) {
            avail = choose_mms_processing(data_list, choice);
        } else if (!wait_reason.empty()) {
            message_writer() << tr("No next step: ") << wait_reason;
        }
    }
    if (avail) {
        mms::processing_data data = data_list[choice];
        bool command_successful = false;
        switch (data.processing) {
            case mms::message_processing::prepare_multisig:
                message_writer() << tr("prepare_multisig");
                command_successful = prepare_multisig_main(std::vector<std::string>(), true);
                break;

            case mms::message_processing::make_multisig: {
                message_writer() << tr("make_multisig");
                size_t number_of_key_sets = data.message_ids.size();
                std::vector<std::string> sig_args(number_of_key_sets + 1);
                sig_args[0] = std::to_string(ms.get_num_required_signers());
                for (size_t i = 0; i < number_of_key_sets; ++i) {
                    mms::message m = ms.get_message_by_id(data.message_ids[i]);
                    sig_args[i + 1] = m.content;
                }
                command_successful = make_multisig_main(sig_args, true);
                break;
            }

            case mms::message_processing::exchange_multisig_keys: {
                message_writer() << tr("exchange_multisig_keys");
                size_t number_of_key_sets = data.message_ids.size();
                // Other than "make_multisig" only the key sets as parameters, no
                // num_required_signers
                std::vector<std::string> sig_args(number_of_key_sets);
                for (size_t i = 0; i < number_of_key_sets; ++i) {
                    mms::message m = ms.get_message_by_id(data.message_ids[i]);
                    sig_args[i] = m.content;
                }
                command_successful = exchange_multisig_keys_main(sig_args, true);
                break;
            }

            case mms::message_processing::create_sync_data: {
                message_writer() << tr("export_multisig_info");
                std::vector<std::string> export_args;
                export_args.push_back("MMS");  // dummy filename
                command_successful = export_multisig_main(export_args, true);
                break;
            }

            case mms::message_processing::process_sync_data: {
                message_writer() << tr("import_multisig_info");
                std::vector<std::string> import_args;
                for (size_t i = 0; i < data.message_ids.size(); ++i) {
                    mms::message m = ms.get_message_by_id(data.message_ids[i]);
                    import_args.push_back(m.content);
                }
                command_successful = import_multisig_main(import_args, true);
                break;
            }

            case mms::message_processing::sign_tx: {
                message_writer() << tr("sign_multisig");
                std::vector<std::string> sign_args;
                mms::message m = ms.get_message_by_id(data.message_ids[0]);
                sign_args.push_back(m.content);
                command_successful = sign_multisig_main(sign_args, true);
                break;
            }

            case mms::message_processing::submit_tx: {
                message_writer() << tr("submit_multisig");
                std::vector<std::string> submit_args;
                mms::message m = ms.get_message_by_id(data.message_ids[0]);
                submit_args.push_back(m.content);
                command_successful = submit_multisig_main(submit_args, true);
                break;
            }

            case mms::message_processing::send_tx: {
                message_writer() << tr("Send tx");
                mms::message m = ms.get_message_by_id(data.message_ids[0]);
                LOCK_IDLE_SCOPE();
                ms.add_message(
                        get_multisig_wallet_state(),
                        data.receiving_signer_index,
                        m.type,
                        mms::message_direction::out,
                        m.content);
                command_successful = true;
                break;
            }

            case mms::message_processing::process_signer_config: {
                message_writer() << tr("Process signer config");
                LOCK_IDLE_SCOPE();
                mms::message m = ms.get_message_by_id(data.message_ids[0]);
                mms::authorized_signer me = ms.get_signer(0);
                mms::multisig_wallet_state state = get_multisig_wallet_state();
                if (!me.auto_config_running) {
                    // If no auto-config is running, the config sent may be unsolicited or
                    // problematic so show what arrived and ask for confirmation before taking it in
                    std::vector<mms::authorized_signer> signers;
                    ms.unpack_signer_config(state, m.content, signers);
                    list_signers(signers);
                    if (!user_confirms(tr("Replace current signer config with the one displayed "
                                          "above?"))) {
                        break;
                    }
                }
                ms.process_signer_config(state, m.content);
                ms.stop_auto_config();
                list_signers(ms.get_all_signers());
                command_successful = true;
                break;
            }

            case mms::message_processing::process_auto_config_data: {
                message_writer() << tr("Process auto config data");
                LOCK_IDLE_SCOPE();
                for (size_t i = 0; i < data.message_ids.size(); ++i) {
                    ms.process_auto_config_data_message(data.message_ids[i]);
                }
                ms.stop_auto_config();
                list_signers(ms.get_all_signers());
                add_signer_config_messages();
                command_successful = true;
                break;
            }

            default: message_writer() << tr("Nothing ready to process"); break;
        }

        if (command_successful) {
            {
                LOCK_IDLE_SCOPE();
                ms.set_messages_processed(data);
                ask_send_all_ready_messages();
            }
        }
    }
}

void simple_wallet::mms_sync(const std::vector<std::string>& args) {
    mms::message_store& ms = m_wallet->get_message_store();
    if (args.size() != 0) {
        fail_msg_writer() << tr("Usage: mms sync");
        return;
    }
    // Force the start of a new sync round, for exceptional cases where something went wrong
    // Can e.g. solve the problem "This signature was made with stale data" after trying to
    // create 2 transactions in a row somehow
    // Code is identical to the code for 'message_processing::create_sync_data'
    message_writer() << tr("export_multisig_info");
    std::vector<std::string> export_args;
    export_args.push_back("MMS");  // dummy filename
    export_multisig_main(export_args, true);
    ask_send_all_ready_messages();
}

void simple_wallet::mms_transfer(const std::vector<std::string>& args) {
    // It's too complicated to check any arguments here, just let 'transfer_main' do the whole job
    transfer_main(Transfer::Normal, args, true);
}

void simple_wallet::mms_delete(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        fail_msg_writer() << tr("Usage: mms delete (<message_id> | all)");
        return;
    }
    LOCK_IDLE_SCOPE();
    mms::message_store& ms = m_wallet->get_message_store();
    if (args[0] == "all") {
        if (user_confirms(tr("Delete all messages?"))) {
            ms.delete_all_messages();
        }
    } else {
        mms::message m;
        bool valid_id = get_message_from_arg(args[0], m);
        if (valid_id) {
            // If only a single message and not all delete even if unsent / unprocessed
            ms.delete_message(m.id);
        }
    }
}

void simple_wallet::mms_send(const std::vector<std::string>& args) {
    if (args.size() == 0) {
        ask_send_all_ready_messages();
        return;
    } else if (args.size() != 1) {
        fail_msg_writer() << tr("Usage: mms send [<message_id>]");
        return;
    }
    LOCK_IDLE_SCOPE();
    mms::message_store& ms = m_wallet->get_message_store();
    mms::message m;
    bool valid_id = get_message_from_arg(args[0], m);
    if (valid_id) {
        ms.send_message(get_multisig_wallet_state(), m.id);
    }
}

void simple_wallet::mms_receive(const std::vector<std::string>& args) {
    if (args.size() != 0) {
        fail_msg_writer() << tr("Usage: mms receive");
        return;
    }
    std::vector<mms::message> new_messages;
    LOCK_IDLE_SCOPE();
    mms::message_store& ms = m_wallet->get_message_store();
    bool avail = ms.check_for_messages(get_multisig_wallet_state(), new_messages);
    if (avail) {
        list_mms_messages(new_messages);
    }
}

void simple_wallet::mms_export(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        fail_msg_writer() << tr("Usage: mms export <message_id>");
        return;
    }
    LOCK_IDLE_SCOPE();
    mms::message_store& ms = m_wallet->get_message_store();
    mms::message m;
    bool valid_id = get_message_from_arg(args[0], m);
    if (valid_id) {
        fs::path filename = tools::utf8_path("mms_message_content");
        if (m_wallet->save_to_file(filename, m.content)) {
            success_msg_writer() << tr("Message content saved to: ") << filename;
        } else {
            fail_msg_writer() << tr("Failed to to save message content");
        }
    }
}

void simple_wallet::mms_note(const std::vector<std::string>& args) {
    mms::message_store& ms = m_wallet->get_message_store();
    if (args.size() == 0) {
        LOCK_IDLE_SCOPE();
        const std::vector<mms::message>& messages = ms.get_all_messages();
        for (size_t i = 0; i < messages.size(); ++i) {
            const mms::message& m = messages[i];
            if ((m.type == mms::message_type::note) && (m.state == mms::message_state::waiting)) {
                show_message(m);
            }
        }
        return;
    }
    if (args.size() < 2) {
        fail_msg_writer() << tr("Usage: mms note [<label> <text>]");
        return;
    }
    uint32_t signer_index;
    bool found = ms.get_signer_index_by_label(args[0], signer_index);
    if (!found) {
        fail_msg_writer() << tr("No signer found with label ") << args[0];
        return;
    }
    std::string note = "";
    for (size_t n = 1; n < args.size(); ++n) {
        if (n > 1) {
            note += " ";
        }
        note += args[n];
    }
    LOCK_IDLE_SCOPE();
    ms.add_message(
            get_multisig_wallet_state(),
            signer_index,
            mms::message_type::note,
            mms::message_direction::out,
            note);
    ask_send_all_ready_messages();
}

void simple_wallet::mms_show(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        fail_msg_writer() << tr("Usage: mms show <message_id>");
        return;
    }
    LOCK_IDLE_SCOPE();
    mms::message_store& ms = m_wallet->get_message_store();
    mms::message m;
    bool valid_id = get_message_from_arg(args[0], m);
    if (valid_id) {
        show_message(m);
    }
}

void simple_wallet::mms_set(const std::vector<std::string>& args) {
    bool set = args.size() == 2;
    bool query = args.size() == 1;
    if (!set && !query) {
        fail_msg_writer() << tr("Usage: mms set <option_name> [<option_value>]");
        return;
    }
    mms::message_store& ms = m_wallet->get_message_store();
    LOCK_IDLE_SCOPE();
    if (args[0] == "auto-send") {
        if (set) {
            bool result;
            bool ok = parse_bool(args[1], result);
            if (ok) {
                ms.set_auto_send(result);
            } else {
                fail_msg_writer() << tr("Wrong option value");
            }
        } else {
            message_writer()
                    << (ms.get_auto_send() ? tr("Auto-send is on") : tr("Auto-send is off"));
        }
    } else {
        fail_msg_writer() << tr("Unknown option");
    }
}

void simple_wallet::mms_help(const std::vector<std::string>& args) {
    if (args.size() > 1) {
        fail_msg_writer() << tr("Usage: mms help [<subcommand>]");
        return;
    }
    std::vector<std::string> help_args;
    help_args.push_back("mms");
    if (args.size() == 1) {
        help_args.push_back(args[0]);
    }
    help(help_args);
}

void simple_wallet::mms_send_signer_config(const std::vector<std::string>& args) {
    if (args.size() != 0) {
        fail_msg_writer() << tr("Usage: mms send_signer_config");
        return;
    }
    mms::message_store& ms = m_wallet->get_message_store();
    if (!ms.signer_config_complete()) {
        fail_msg_writer() << tr("Signer config not yet complete");
        return;
    }
    LOCK_IDLE_SCOPE();
    add_signer_config_messages();
    ask_send_all_ready_messages();
}

void simple_wallet::mms_start_auto_config(const std::vector<std::string>& args) {
    mms::message_store& ms = m_wallet->get_message_store();
    uint32_t other_signers = ms.get_num_authorized_signers() - 1;
    size_t args_size = args.size();
    if ((args_size != 0) && (args_size != other_signers)) {
        fail_msg_writer() << tr("Usage: mms start_auto_config [<label> <label> ...]");
        return;
    }
    if ((args_size == 0) && !ms.signer_labels_complete()) {
        fail_msg_writer() << tr(
                "There are signers without a label set. Complete labels before auto-config or "
                "specify them as parameters here.");
        return;
    }
    mms::authorized_signer me = ms.get_signer(0);
    if (me.auto_config_running) {
        if (!user_confirms(tr("Auto-config is already running. Cancel and restart?"))) {
            return;
        }
    }
    LOCK_IDLE_SCOPE();
    mms::multisig_wallet_state state = get_multisig_wallet_state();
    if (args_size != 0) {
        // Set (or overwrite) all the labels except "me" from the arguments
        for (uint32_t i = 1; i < (other_signers + 1); ++i) {
            ms.set_signer(state, i, args[i - 1], std::nullopt, std::nullopt);
        }
    }
    ms.start_auto_config(state);
    // List the signers to show the generated auto-config tokens
    list_signers(ms.get_all_signers());
}

void simple_wallet::mms_stop_auto_config(const std::vector<std::string>& args) {
    if (args.size() != 0) {
        fail_msg_writer() << tr("Usage: mms stop_auto_config");
        return;
    }
    if (!user_confirms(tr("Delete any auto-config tokens and stop auto-config?"))) {
        return;
    }
    mms::message_store& ms = m_wallet->get_message_store();
    LOCK_IDLE_SCOPE();
    ms.stop_auto_config();
}

void simple_wallet::mms_auto_config(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        fail_msg_writer() << tr("Usage: mms auto_config <auto_config_token>");
        return;
    }
    mms::message_store& ms = m_wallet->get_message_store();
    std::string adjusted_token;
    if (!ms.check_auto_config_token(args[0], adjusted_token)) {
        fail_msg_writer() << tr("Invalid auto-config token");
        return;
    }
    mms::authorized_signer me = ms.get_signer(0);
    if (me.auto_config_running) {
        if (!user_confirms(tr("Auto-config already running. Cancel and restart?"))) {
            return;
        }
    }
    LOCK_IDLE_SCOPE();
    ms.add_auto_config_data_message(get_multisig_wallet_state(), adjusted_token);
    ask_send_all_ready_messages();
}

bool simple_wallet::mms(const std::vector<std::string>& args) {
    try {
        m_wallet->get_multisig_wallet_state();
    } catch (const std::exception& e) {
        fail_msg_writer() << tr("MMS not available in this wallet");
        return true;
    }

    try {
        mms::message_store& ms = m_wallet->get_message_store();
        if (args.size() == 0) {
            mms_info(args);
            return true;
        }

        const std::string& sub_command = args[0];
        std::vector<std::string> mms_args = args;
        mms_args.erase(mms_args.begin());

        if (sub_command == "init") {
            mms_init(mms_args);
            return true;
        }
        if (!ms.get_active()) {
            fail_msg_writer() << tr(
                    "The MMS is not active. Activate using the \"mms init\" command");
            return true;
        } else if (sub_command == "info") {
            mms_info(mms_args);
        } else if (sub_command == "signer") {
            mms_signer(mms_args);
        } else if (sub_command == "list") {
            mms_list(mms_args);
        } else if (sub_command == "next") {
            mms_next(mms_args);
        } else if (sub_command == "sync") {
            mms_sync(mms_args);
        } else if (sub_command == "transfer") {
            mms_transfer(mms_args);
        } else if (sub_command == "delete") {
            mms_delete(mms_args);
        } else if (sub_command == "send") {
            mms_send(mms_args);
        } else if (sub_command == "receive") {
            mms_receive(mms_args);
        } else if (sub_command == "export") {
            mms_export(mms_args);
        } else if (sub_command == "note") {
            mms_note(mms_args);
        } else if (sub_command == "show") {
            mms_show(mms_args);
        } else if (sub_command == "set") {
            mms_set(mms_args);
        } else if (sub_command == "help") {
            mms_help(mms_args);
        } else if (sub_command == "send_signer_config") {
            mms_send_signer_config(mms_args);
        } else if (sub_command == "start_auto_config") {
            mms_start_auto_config(mms_args);
        } else if (sub_command == "stop_auto_config") {
            mms_stop_auto_config(mms_args);
        } else if (sub_command == "auto_config") {
            mms_auto_config(mms_args);
        } else {
            fail_msg_writer() << tr("Invalid MMS subcommand");
        }
    } catch (const tools::error::no_connection_to_daemon& e) {
        fail_msg_writer() << tr("Error in MMS command: ") << e.what() << " " << e.request();
    } catch (const std::exception& e) {
        fail_msg_writer() << tr("Error in MMS command: ") << e.what();
        PRINT_USAGE(USAGE_MMS);
        return true;
    }
    return true;
}
// End MMS
// ------------------------------------------------------------------------------------------------
