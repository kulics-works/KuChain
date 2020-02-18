BlockChain . {
    System
    System.Security.Cryptography
    System.Text
    System.Linq

    Newtonsoft.Json
}

Main : (args [.]str->) {
    print("Hello World!")
    # 创世
    SHA512 = SHA512Managed{}
    Hash = SHA512.ComputeHash(("Hello World!").to_bytes())
    trs = generate_transactions()
    blk = block{
        parent_hash = Hash.to_hex()
        time = get_time()
        height = 0
        nonce = 0
        root_hash = generate_merkle_tree(trs).hash
        transactions = trs
    }
    json = JsonConvert.SerializeObject(blk)
    print("hash:  ", blk.to_hash(), "\ncontent:  ", json.to_str())
    @ true {
        blk = generate_block(blk.to_hash(), blk.height)
        blk.nonce = proof_of_work(blk)
        json = JsonConvert.SerializeObject(blk)
        print("hash:  ", blk.to_hash(), "\ncontent:  ", json.to_str())
    }
}

block : $ (me) {
    parent_hash str
    time int
    height int
    root_hash str
    transactions []transaction
    nonce int

    to_hash : (->v str) {
        json = JsonConvert.SerializeObject({
            parent_hash = me.parent_hash
            time = me.time
            height = me.height
            root_hash = me.root_hash
        })
        SHA512 = SHA512Managed{}
        Hash = SHA512.ComputeHash(json.to_bytes())
        SHA512.Clear()
        <- Hash.to_hex()
    }

    work_hash : (->v str) {
        json = JsonConvert.SerializeObject({
            parent_hash = me.parent_hash
            time = me.time
            height = me.height
            root_hash = me.root_hash
            })
        SHA512 = SHA512Managed{}
        Hash = SHA512.ComputeHash(json.to_bytes())
        SHA512.Clear()
        <- Hash.to_hex()
    }
}

transaction : $ (me) {
    sign str
    to str
    mount int
    time int

    to_sign : (->) {
        ! ecckey = ECDsa.Create()
        json = JsonConvert.SerializeObject({
            to = me.to
            mount = me.mount
            time = me.time
        })
        SHA512 = SHA512Managed{}
        Hash = SHA512.ComputeHash(json.to_bytes())
        SHA512.Clear()
        me.sign = ecckey.SignHash(Hash).to_hex()
    }

    to_hash : (->v str) {
        json = JsonConvert.SerializeObject(me)
        SHA512 = SHA512Managed{}
        Hash = SHA512.ComputeHash(json.to_bytes())
        SHA512.Clear()
        <- Hash.to_hex()
    }
}

generate_transaction : (->v transaction) {
    tx = transaction{
            to = "kulics"
            mount = 1
            time = get_time()
        }
    tx.to_sign()
    <- tx
}

generate_transactions : (->v []transaction) {
    list = []transaction{}
    @ i = 0 ~ 9.. {
        list.add(generate_transaction())
    }
    <- list
}

generate_block : (parent_hash str, height int->v block) {
    trs = generate_transactions()
    <- block{
        time = get_time()
        parent_hash = parent_hash
        height = height+1
        transactions = trs
        root_hash = generate_merkle_tree(trs).hash
    }
}

generate_merkle_tree : (trs []transaction->node merkle_node) {
    nodes = []merkle_node{}
    @ i = trs.. {
        nodes.add(merkle_node{
            hash = i.to_hash()
        })
    }
    <- generate_node(nodes)
}

generate_node : (nodes []merkle_node->node merkle_node) {
    ? nodes.length == 1 {
        <- nodes[0]
    }
    list = []merkle_node{}
    @ i = 0 ~(2) nodes.length - 1.. {
        root merkle_node
        ? i + 1 < nodes.length {
            root = merge_node(nodes[i], nodes[i+1])
        } _ {
            root = merge_node(nodes[i], nodes[i])
        }
        list.add(root)
    }
    <- generate_node(list)
}

merge_node : (left merkle_node, right merkle_node -> root merkle_node) {
    SHA512 = SHA512Managed{}
    Hash = SHA512.ComputeHash((left.hash+right.hash).to_bytes())
    SHA512.Clear()
    <- merkle_node{
        hash = Hash.to_hex()
        left = left
        right = right
    }
}

proof_of_work : (blk block->nonce int) {
    hash = blk.work_hash()
    nonce = 0
    SHA512 = SHA512Managed{}
    Hash = SHA512.ComputeHash((hash+nonce.to_str()).to_bytes())
    @ ~is_work_enough(Hash.to_hex()) {
        nonce += 1
        Hash = SHA512.ComputeHash((hash+nonce.to_str()).to_bytes())
    }
    print("work nonce:  ", Hash.to_hex())
    SHA512.Clear()
    <- nonce
}

is_work_enough : (hash str->b bool) {
    <- hash.sub_str(0, 5) == "00000"
}
#:DateTime
# 获取起始时间
Epoch = DateTime(1970, 1, 1)

get_time : (->v int) {
    # 相减得出unix时间
    <- ((DateTime.UtcNow - Epoch).TotalMilliseconds / 1000) int!
}

merkle_node : $ {
    hash str
    left ?merkle_node
    right ?merkle_node
}
