
#include "../qcommon/q_shared.h"
#include "../qcommon/qcommon.h"
#include "server.h"

// TTimo: unused, commenting out to make gcc happy
#if 1
/*
==============
SV_Netchan_Encode

	// first four bytes of the data are always:
	long reliableAcknowledge;

==============
*/
static void SV_Netchan_Encode( client_t *client, msg_t *msg, byte *string ) {
	int reliableAcknowledge, i, index;
	byte key;
	int	srdc, sbit;
	qboolean soob;

	if ( msg->cursize < SV_ENCODE_START ) {
		return;
	}

		srdc = msg->readcount;
		sbit = msg->bit;
		soob = msg->oob;

		msg->bit = 0;
		msg->readcount = 0;
		msg->oob = qfalse;

	reliableAcknowledge = MSG_ReadLong(msg);

		msg->oob = soob;
		msg->bit = sbit;
		msg->readcount = srdc;

	index = 0;
	// xor the client challenge with the netchan sequence number
	key = client->challenge ^ client->netchan.outgoingSequence;
	for (i = SV_ENCODE_START; i < msg->cursize; i++) {
		// modify the key with the last received and with this message acknowledged client command
		if (!string[index])
			index = 0;
		if (string[index] > 127 || string[index] == '%') {
			key ^= '.' << (i & 1);
		}
		else {
			key ^= string[index] << (i & 1);
		}
		index++;
		// encode the data with this key
		*(msg->data + i) = *(msg->data + i) ^ key;
	}
}

/*
==============
SV_Netchan_Decode

	// first 12 bytes of the data are always:
	long serverId;
	long messageAcknowledge;
	long reliableAcknowledge;

==============
*/
static void SV_Netchan_Decode( client_t *client, msg_t *msg ) {
	int serverId, messageAcknowledge, reliableAcknowledge;
	int i, index, srdc, sbit;
	byte key, *string;
	qboolean soob;

		srdc = msg->readcount;
		sbit = msg->bit;
		soob = msg->oob;

		msg->oob = qfalse;

		serverId = MSG_ReadLong(msg);
	messageAcknowledge = MSG_ReadLong(msg);
	reliableAcknowledge = MSG_ReadLong(msg);

		msg->oob = soob;
		msg->bit = sbit;
		msg->readcount = srdc;

	string = (byte *)client->reliableCommands[ reliableAcknowledge & (MAX_RELIABLE_COMMANDS-1) ];
	index = 0;
	//
	key = client->challenge ^ serverId ^ messageAcknowledge;
	for (i = msg->readcount + SV_DECODE_START; i < msg->cursize; i++) {
		// modify the key with the last sent and acknowledged server command
		if (!string[index])
			index = 0;
		if (string[index] > 127 || string[index] == '%') {
			key ^= '.' << (i & 1);
		}
		else {
			key ^= string[index] << (i & 1);
		}
		index++;
		// decode the data with this key
		*(msg->data + i) = *(msg->data + i) ^ key;
	}
}
#endif

/*
=================
SV_Netchan_TransmitNextFragment
=================
*/
void SV_Netchan_TransmitNextFragment( client_t *client ) {
	if ( client->netchan.unsentFragments ) {
		Netchan_TransmitNextFragment( &client->netchan );
	}
	else if ( client->netchan_start_queue ) {
		netchan_buffer_t *netbuf;

		// make sure the netchan queue has been properly initialized (you never know)
		if ( !client->netchan_end_queue ) {
			Com_Error(ERR_DROP, "netchan queue is not properly initialized in SV_Netchan_TransmitNextFragment\n");
		}

		// the last fragment was transmitted, check wether we have queued messages
		Com_DPrintf("#462 Netchan_TransmitNextFragment: popping a queued message for transmit\n");
		netbuf = client->netchan_start_queue;
		SV_Netchan_Encode( client, &netbuf->msg, (byte*)netbuf->lastClientCommandString );
		Netchan_Transmit( &client->netchan, netbuf->msg.cursize, netbuf->msg.data );

		// pop from queue
		client->netchan_start_queue = netbuf->next;
		if (!client->netchan_start_queue) {
			Com_DPrintf("#462 Netchan_TransmitNextFragment: emptied queue\n");
			client->netchan_end_queue = &client->netchan_start_queue;
		}
		else {
			Com_DPrintf("#462 Netchan_TransmitNextFragment: remaining queued message\n");
		}
		Z_Free(netbuf);
	}
}


/*
===============
SV_Netchan_Transmit
================
*/

//extern byte chksum[65536];
void SV_Netchan_Transmit( client_t *client, msg_t *msg) {	//int length, const byte *data ) {
	MSG_WriteByte( msg, svc_EOF );
	if (client->netchan.unsentFragments || client->netchan_start_queue) {
		netchan_buffer_t *netbuf;
		Com_DPrintf("#462 SV_Netchan_Transmit: unsent fragments, stacked\n");
		netbuf = (netchan_buffer_t *)Z_Malloc(sizeof(netchan_buffer_t), TAG_NETCHAN, qtrue);
		// store the msg, we can't store it encoded, as the encoding depends on stuff we still have to finish sending
		MSG_Copy(&netbuf->msg, netbuf->msgBuffer, sizeof( netbuf->msgBuffer ), msg);
		// also store the lastClientCommandString as messages refer to the last reliable command we received and if we receive
		// a new client command while messages are in the queue we can't encode them with the new command
		Q_strncpyz( netbuf->lastClientCommandString, client->lastClientCommandString, sizeof(netbuf->lastClientCommandString) );
		netbuf->next = NULL;
		// insert it in the queue, the message will be encoded and sent later
		*client->netchan_end_queue = netbuf;
		client->netchan_end_queue = &(*client->netchan_end_queue)->next;
	} else {
		SV_Netchan_Encode( client, msg, (byte*)client->lastClientCommandString );
		Netchan_Transmit( &client->netchan, msg->cursize, msg->data );
	}
}

/*
=================
Netchan_SV_Process
=================
*/
qboolean SV_Netchan_Process( client_t *client, msg_t *msg ) {
	int ret;
//	int i;
	ret = Netchan_Process( &client->netchan, msg );
	if (!ret)
		return qfalse;
	SV_Netchan_Decode( client, msg );
//	Huff_Decompress( msg, SV_DECODE_START );
//	for(i=SV_DECODE_START+msg->readcount;i<msg->cursize;i++) {
//		if (msg->data[i] != chksum[i-(SV_DECODE_START+msg->readcount)]) {
//			Com_Error(ERR_DROP,"bad");
//		}
//	}
	return qtrue;
}

