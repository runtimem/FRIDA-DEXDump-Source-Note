/*
* Author: hluwa <hluwa888@gmail.com>
* HomePage: https://github.com/hluwa
* CreatedTime: 2020/1/7 20:44
* */


// 通过 maps 验证
// 32+4+4+4+4+4  = 0x34
var enable_deep_search = false;

function verify_by_maps(dexptr, mapsptr) {
    var maps_offset = dexptr.add(0x34).readUInt();
    var maps_size = mapsptr.readUInt();
    for (var i = 0; i < maps_size; i++) {
        var item_type = mapsptr.add(4 + i * 0xC).readU16();

        // TYPE_MAP_LIST == 4096
        // https://cs.android.com/android/platform/superproject/+/master:dalvik/dx/src/com/android/dx/dex/file/MapItem.java;l=66?q=TYPE_MAP_LIST&ss=android
        // maps_item 最后一个item为 TYPE_MAP_LIST 类型
        if (item_type === 4096) {
            var map_offset = mapsptr.add(4 + i * 0xC + 8).readUInt();
            if (maps_offset === map_offset) {
                return true;
            }
        }
    }
    return false;
}

// fileSize 可能被伪造，需要通过maps获取真实大小
function get_dex_real_size(dexptr, range_base, range_end) {
    // 获取 file_size 字段 from dex header
    var dex_size = dexptr.add(0x20).readUInt();



    var maps_address = get_maps_address(dexptr, range_base, range_end);
    if (!maps_address) {
        return dex_size;
    }

    var maps_end = get_maps_end(maps_address, range_base, range_end);
    if (!maps_end) {
        return dex_size;
    }

    return maps_end - dexptr
}


function get_maps_address(dexptr, range_base, range_end) {
    // 32+4+4+4+4+4  = 0x34
    // 0x34 是maps_offset对于 dex 的偏移
    var maps_offset = dexptr.add(0x34).readUInt();
    if (maps_offset === 0) {
        return null;
    }

    var maps_address = dexptr.add(maps_offset);
    if (maps_address < range_base || maps_address > range_end) {
        return null;
    }

    return maps_address;
}

function get_maps_end(maps, range_base, range_end) {
    //读取 map_list size
    var maps_size = maps.readUInt();
    if (maps_size < 2 || maps_size > 50) {
        return null;
    }
    //size + item * 0xc
    var maps_end = maps.add(maps_size * 0xC + 4);
    if (maps_end < range_base || maps_end > range_end) {
        return null;
    }

    return maps_end;
}

// 验证是否为dex
function verify(dexptr, range, enable_verify_maps) {

    if (range != null) {
        // 确定起始地址
        var range_end = range.base.add(range.size);

        // verify header_size  验证 范围是否大于 header_size，否则返回flase 
        if (dexptr.add(0x70) > range_end) {
            return false;
        }

        // 在运行时中，fileSize字段可以被清空，所以不可信
        // In runtime, the fileSize is can to be clean, so it's not trust.
        // verify file_size
        // var dex_size = dexptr.add(0x20).readUInt();
        // if (dexptr.add(dex_size) > range_end) {
        //     return false;
        // }

        if (enable_verify_maps) {

            var maps_address = get_maps_address(dexptr, range.base, range_end);
            if (!maps_address) {
                return false;
            }

            var maps_end = get_maps_end(maps_address, range.base, range_end);
            if (!maps_end) {
                return false;
            }
            //  通过 maps判定dex
            return verify_by_maps(dexptr, maps_address)
        } else {
             // 判定 string_off
            return dexptr.add(0x3C).readUInt() === 0x70;
        }
    }

    return false;


}

rpc.exports = {
    memorydump: function memorydump(address, size) {
        return new NativePointer(address).readByteArray(size);
    },
    switchmode: function switchmode(bool) {
        enable_deep_search = bool;
    },
    scandex: function scandex() {
        // 扫描进程内存中的dex
        var result = [];
        // 枚举所有具有“读”权限的内存空间
        Process.enumerateRanges('r--').forEach(function (range) {
            try {
                // 匹配 dex magic number
                Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function (match) {

                     // 系统文件不导出
                    if (range.file && range.file.path
                        && (// range.file.path.startsWith("/data/app/") ||
                            range.file.path.startsWith("/data/dalvik-cache/") ||
                            range.file.path.startsWith("/system/"))) {
                        return;
                    }
                    //  验证dex 并保存到 results     
                    if (verify(match.address, range, false)) {
                        // 获取真正的dex大小
                        var dex_size = get_dex_real_size(match.address, range.base, range.base.add(range.size));
                        result.push({
                            "addr": match.address,
                            "size": dex_size
                        });

                        //整块内存区域体积 - （匹配的内存块地址 - 整块内存区域的基地址）
                        // dump内存段末尾
                        var max_size = range.size - match.address.sub(range.base);
                        if (enable_deep_search && max_size != dex_size) {
                            result.push({
                                "addr": match.address,
                                "size": max_size
                            });
                        }
                    }
                });

                if (enable_deep_search) {
                    // 开启深度搜索

                    // 搜索  string_ids_off
                    Memory.scanSync(range.base, range.size, "70 00 00 00").forEach(function (match) {
                        // 0x3c是string_ids_off 对于dex基地址的偏移，这里计算出理论上的dex起始地址
                        var dex_base = match.address.sub(0x3C);
                        // 判断是否容纳
                        if (dex_base < range.base) {
                            return
                        }

                        // 针对抹头dex的处理
                        // 正常dex 不参与此流程
                        if (dex_base.readCString(4) != "dex\n" && verify(dex_base, range, true)) {
                            
                            //抹头 -> 通过maps得到最大地址
                            var real_dex_size = get_dex_real_size(dex_base, range.base, range.base.add(range.size));
                            result.push({
                                "addr": dex_base,
                                "size": real_dex_size
                            });

                            // ？ 直接dump到末尾
                            var max_size = range.size - dex_base.sub(range.base);
                            if (max_size != real_dex_size) {
                                result.push({
                                    "addr": match.address,
                                    "size": max_size
                                });
                            }
                        }
                    })
                } else {
                    // 未开启深度搜索
                    if (range.base.readCString(4) != "dex\n" && verify(range.base, range, true)) {
                        var real_dex_size = get_dex_real_size(range.base, range.base, range.base.add(range.size));
                        result.push({
                            "addr": range.base,
                            "size": real_dex_size
                        });
                    }
                }

            } catch (e) {
            }
        });

        return result;
    }
};
