//
// Created by root on 2026/6/22.
//

#include "SyncRiskFileConfig.hpp"

SyncRiskFileConfig& SyncRiskFileConfig::instance()
{
    static SyncRiskFileConfig inst;
    return inst;
}
